package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	builderApi "github.com/attestantio/go-builder-client/api"
	denebApi "github.com/attestantio/go-builder-client/api/deneb"
	builderSpec "github.com/attestantio/go-builder-client/spec"
	eth2ApiV1Bellatrix "github.com/attestantio/go-eth2-client/api/v1/bellatrix"
	eth2ApiV1Capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	eth2ApiV1Deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	eth2ApiV1Electra "github.com/attestantio/go-eth2-client/api/v1/electra"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/flashbots/mev-boost/config"
	"github.com/flashbots/mev-boost/server/params"
	"github.com/flashbots/mev-boost/server/types"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type Payload interface {
	*eth2ApiV1Bellatrix.SignedBlindedBeaconBlock |
		*eth2ApiV1Capella.SignedBlindedBeaconBlock |
		*eth2ApiV1Deneb.SignedBlindedBeaconBlock |
		*eth2ApiV1Electra.SignedBlindedBeaconBlock
}

var (
	errInvalidVersion      = errors.New("invalid version")
	errEmptyPayload        = errors.New("empty payload")
	errInvalidBlockHash    = errors.New("invalid block hash")
	errLengthsMismatch     = errors.New("blobs/commitments/proofs lengths mismatch")
	errCommitmentsMismatch = errors.New("commitments mismatch")
)

// processPayload requests the payload (execution payload, blobs bundle, etc) from the relays
func processPayload[P Payload](m *BoostService, log *logrus.Entry, ua UserAgent, blindedBlock P) (*builderApi.VersionedSubmitBlindedBlockResponse, bidResp) {
	var (
		slot      = slot(blindedBlock)
		blockHash = blockHash(blindedBlock)
	)

	// Get the currentSlotUID for this slot
	currentSlotUID := ""
	m.slotUIDLock.Lock()
	if m.slotUID.slot == slot {
		currentSlotUID = m.slotUID.uid.String()
	} else {
		log.Warnf("latest slotUID is for slot %d rather than payload slot %d", m.slotUID.slot, slot)
	}
	m.slotUIDLock.Unlock()

	// Prepare logger
	log = prepareLogger(log, blindedBlock, ua, currentSlotUID)

	// Log how late into the slot the request starts
	slotStartTimestamp := m.genesisTime + uint64(slot)*config.SlotTimeSec
	msIntoSlot := uint64(time.Now().UTC().UnixMilli()) - slotStartTimestamp*1000
	log.WithFields(logrus.Fields{
		"genesisTime": m.genesisTime,
		"slotTimeSec": config.SlotTimeSec,
		"msIntoSlot":  msIntoSlot,
	}).Infof("submitBlindedBlock request start - %d milliseconds into slot %d", msIntoSlot, slot)

	// Get the bid!
	m.bidsLock.Lock()
	originalBid := m.bids[bidKey(slot, blockHash)]
	m.bidsLock.Unlock()
	if originalBid.response.IsEmpty() {
		log.Error("no bid for this getPayload payload found, was getHeader called before?")
	} else if len(originalBid.relays) == 0 {
		log.Warn("bid found but no associated relays")
	}

	// Add request headers
	headers := map[string]string{
		HeaderKeySlotUID:      currentSlotUID,
		HeaderStartTimeUnixMS: fmt.Sprintf("%d", time.Now().UTC().UnixMilli()),
	}

	// Prepare for requests
	resultCh := make(chan *builderApi.VersionedSubmitBlindedBlockResponse, len(m.relays))
	var received atomic.Bool
	go func() {
		// Make sure we receive a response within the timeout
		time.Sleep(m.httpClientGetPayload.Timeout)
		resultCh <- nil
	}()

	// Prepare the request context, which will be canceled after the first successful response from a relay
	requestCtx, requestCtxCancel := context.WithCancel(context.Background())
	defer requestCtxCancel()

	for _, relay := range m.relays {
		go func(relay types.RelayEntry) {
			url := relay.GetURI(params.PathGetPayload)
			log := log.WithField("url", url)
			log.Debug("calling getPayload")

			responsePayload := new(builderApi.VersionedSubmitBlindedBlockResponse)
			_, err := SendHTTPRequestWithRetries(requestCtx, m.httpClientGetPayload, http.MethodPost, url, ua, headers, blindedBlock, responsePayload, m.requestMaxRetries, log)
			if err != nil {
				if errors.Is(requestCtx.Err(), context.Canceled) {
					// This is expected if the payload has already been received by another relay
					log.Info("request was canceled")
				} else {
					log.WithError(err).Error("error making request to relay")
				}
				return
			}

			if err := verifyPayload(blindedBlock, log, responsePayload); err != nil {
				log.WithError(err).Error("payload verification failed")
				return
			}

			requestCtxCancel()
			if received.CompareAndSwap(false, true) {
				resultCh <- responsePayload
				log.Info("received payload from relay")
			} else {
				log.Trace("Discarding response, already received a correct response")
			}
		}(relay)
	}

	// Wait for the first request to complete
	result := <-resultCh

	return result, originalBid
}

// verifyPayload checks that the payload is valid
func verifyPayload[P Payload](payload P, log *logrus.Entry, response *builderApi.VersionedSubmitBlindedBlockResponse) error {
	switch block := any(payload).(type) {
	case *eth2ApiV1Bellatrix.SignedBlindedBeaconBlock:
		if response.Version != spec.DataVersionBellatrix {
			return errInvalidVersion
		}
		if response.Bellatrix == nil ||
			response.Bellatrix.BlockHash == nilHash {
			return errEmptyPayload
		}
		if err := verifyBlockHash(log, payload, response.Bellatrix.BlockHash); err != nil {
			return err
		}
	case *eth2ApiV1Capella.SignedBlindedBeaconBlock:
		if response.Version != spec.DataVersionCapella {
			return errInvalidVersion
		}
		if response.Capella == nil ||
			response.Capella.BlockHash == nilHash {
			return errEmptyPayload
		}
		if err := verifyBlockHash(log, payload, response.Capella.BlockHash); err != nil {
			return err
		}
	case *eth2ApiV1Deneb.SignedBlindedBeaconBlock:
		if response.Version != spec.DataVersionDeneb {
			return errInvalidVersion
		}
		if response.Deneb == nil ||
			response.Deneb.ExecutionPayload == nil ||
			response.Deneb.ExecutionPayload.BlockHash == nilHash ||
			response.Deneb.BlobsBundle == nil {
			return errEmptyPayload
		}
		if err := verifyBlockHash(log, payload, response.Deneb.ExecutionPayload.BlockHash); err != nil {
			return err
		}
		if err := verifyKZGCommitments(log, response.Deneb.BlobsBundle, block.Message.Body.BlobKZGCommitments); err != nil {
			return err
		}
	case *eth2ApiV1Electra.SignedBlindedBeaconBlock:
		if response.Version != spec.DataVersionElectra {
			return errInvalidVersion
		}
		if response.Electra == nil ||
			response.Electra.ExecutionPayload == nil ||
			response.Electra.ExecutionPayload.BlockHash == nilHash ||
			response.Electra.BlobsBundle == nil {
			return errEmptyPayload
		}
		if err := verifyBlockHash(log, payload, response.Electra.ExecutionPayload.BlockHash); err != nil {
			return err
		}
		if err := verifyKZGCommitments(log, response.Electra.BlobsBundle, block.Message.Body.BlobKZGCommitments); err != nil {
			return err
		}
	}
	return nil
}

// verifyBlockHash checks that the block hash is correct
func verifyBlockHash[P Payload](log *logrus.Entry, payload P, executionPayloadHash phase0.Hash32) error {
	if blockHash(payload) != executionPayloadHash {
		log.WithFields(logrus.Fields{
			"responseBlockHash": executionPayloadHash.String(),
		}).Error("requestBlockHash does not equal responseBlockHash")
		return errInvalidBlockHash
	}
	return nil
}

// verifyKZGCommitments checks that blobs bundle is valid
func verifyKZGCommitments(log *logrus.Entry, blobs *denebApi.BlobsBundle, commitments []deneb.KZGCommitment) error {
	// Ensure that blobs are valid and matches the request
	if len(commitments) != len(blobs.Blobs) || len(commitments) != len(blobs.Commitments) || len(commitments) != len(blobs.Proofs) {
		log.WithFields(logrus.Fields{
			"requestBlobCommitments":  len(commitments),
			"responseBlobs":           len(blobs.Blobs),
			"responseBlobCommitments": len(blobs.Commitments),
			"responseBlobProofs":      len(blobs.Proofs),
		}).Error("different lengths for blobs/commitments/proofs")
		return errLengthsMismatch
	}

	for i, commitment := range commitments {
		if commitment != blobs.Commitments[i] {
			log.WithFields(logrus.Fields{
				"index":                  i,
				"requestBlobCommitment":  commitment.String(),
				"responseBlobCommitment": blobs.Commitments[i].String(),
			}).Error("requestBlobCommitment does not equal responseBlobCommitment")
			return errCommitmentsMismatch
		}
	}
	return nil
}

// prepareLogger adds relevant fields to the logger
func prepareLogger[P Payload](log *logrus.Entry, payload P, userAgent UserAgent, slotUID string) *logrus.Entry {
	switch block := any(payload).(type) {
	case *eth2ApiV1Bellatrix.SignedBlindedBeaconBlock:
		return log.WithFields(logrus.Fields{
			"ua":         userAgent,
			"slot":       block.Message.Slot,
			"blockHash":  block.Message.Body.ExecutionPayloadHeader.BlockHash.String(),
			"parentHash": block.Message.Body.ExecutionPayloadHeader.ParentHash.String(),
			"slotUID":    slotUID,
		})
	case *eth2ApiV1Capella.SignedBlindedBeaconBlock:
		return log.WithFields(logrus.Fields{
			"ua":         userAgent,
			"slot":       block.Message.Slot,
			"blockHash":  block.Message.Body.ExecutionPayloadHeader.BlockHash.String(),
			"parentHash": block.Message.Body.ExecutionPayloadHeader.ParentHash.String(),
			"slotUID":    slotUID,
		})
	case *eth2ApiV1Deneb.SignedBlindedBeaconBlock:
		return log.WithFields(logrus.Fields{
			"ua":         userAgent,
			"slot":       block.Message.Slot,
			"blockHash":  block.Message.Body.ExecutionPayloadHeader.BlockHash.String(),
			"parentHash": block.Message.Body.ExecutionPayloadHeader.ParentHash.String(),
			"slotUID":    slotUID,
		})
	case *eth2ApiV1Electra.SignedBlindedBeaconBlock:
		return log.WithFields(logrus.Fields{
			"ua":         userAgent,
			"slot":       block.Message.Slot,
			"blockHash":  block.Message.Body.ExecutionPayloadHeader.BlockHash.String(),
			"parentHash": block.Message.Body.ExecutionPayloadHeader.ParentHash.String(),
			"slotUID":    slotUID,
		})
	}
	return nil
}

// slot returns the block's slot
func slot[P Payload](payload P) phase0.Slot {
	switch block := any(payload).(type) {
	case *eth2ApiV1Bellatrix.SignedBlindedBeaconBlock:
		return block.Message.Slot
	case *eth2ApiV1Capella.SignedBlindedBeaconBlock:
		return block.Message.Slot
	case *eth2ApiV1Deneb.SignedBlindedBeaconBlock:
		return block.Message.Slot
	case *eth2ApiV1Electra.SignedBlindedBeaconBlock:
		return block.Message.Slot
	}
	return 0
}

// blockHash returns the block's hash
func blockHash[P Payload](payload P) phase0.Hash32 {
	switch block := any(payload).(type) {
	case *eth2ApiV1Bellatrix.SignedBlindedBeaconBlock:
		return block.Message.Body.ExecutionPayloadHeader.BlockHash
	case *eth2ApiV1Capella.SignedBlindedBeaconBlock:
		return block.Message.Body.ExecutionPayloadHeader.BlockHash
	case *eth2ApiV1Deneb.SignedBlindedBeaconBlock:
		return block.Message.Body.ExecutionPayloadHeader.BlockHash
	case *eth2ApiV1Electra.SignedBlindedBeaconBlock:
		return block.Message.Body.ExecutionPayloadHeader.BlockHash
	}
	return nilHash
}

// bidKey makes a map key for a specific bid
func bidKey(slot phase0.Slot, blockHash phase0.Hash32) string {
	return fmt.Sprintf("%v%v", slot, blockHash)
}

// getHeader requests a bid from each relay and returns the most profitable one
func (m *BoostService) getHeader(log *logrus.Entry, ua UserAgent, slot phase0.Slot, pubkey, parentHashHex string) (bidResp, error) {
	// Ensure arguments are valid
	if len(pubkey) != 98 {
		return bidResp{}, errInvalidPubkey
	}
	if len(parentHashHex) != 66 {
		return bidResp{}, errInvalidHash
	}

	// Make sure we have a uid for this slot
	m.slotUIDLock.Lock()
	if m.slotUID.slot < slot {
		m.slotUID.slot = slot
		m.slotUID.uid = uuid.New()
	}
	slotUID := m.slotUID.uid
	m.slotUIDLock.Unlock()
	log = log.WithField("slotUID", slotUID)

	// Log how late into the slot the request starts
	slotStartTimestamp := m.genesisTime + uint64(slot)*config.SlotTimeSec
	msIntoSlot := uint64(time.Now().UTC().UnixMilli()) - slotStartTimestamp*1000
	log.WithFields(logrus.Fields{
		"genesisTime": m.genesisTime,
		"slotTimeSec": config.SlotTimeSec,
		"msIntoSlot":  msIntoSlot,
	}).Infof("getHeader request start - %d milliseconds into slot %d", msIntoSlot, slot)

	// Add request headers
	headers := map[string]string{
		HeaderKeySlotUID:      slotUID.String(),
		HeaderStartTimeUnixMS: fmt.Sprintf("%d", time.Now().UTC().UnixMilli()),
	}

	var (
		mu sync.Mutex
		wg sync.WaitGroup

		// The final response, containing the highest bid (if any)
		result = bidResp{}

		// Relays that sent the bid for a specific blockHash
		relays = make(map[BlockHashHex][]types.RelayEntry)
	)

	// Request a bid from each relay
	for _, relay := range m.relays {
		wg.Add(1)
		go func(relay types.RelayEntry) {
			defer wg.Done()

			// Build the request URL
			url := relay.GetURI(fmt.Sprintf("/eth/v1/builder/header/%d/%s/%s", slot, parentHashHex, pubkey))
			log := log.WithField("url", url)

			// Send the get bid request to the relay
			bid := new(builderSpec.VersionedSignedBuilderBid)
			code, err := SendHTTPRequest(context.Background(), m.httpClientGetHeader, http.MethodGet, url, ua, headers, nil, bid)
			if err != nil {
				log.WithError(err).Warn("error making request to relay")
				return
			}
			if code == http.StatusNoContent {
				log.Debug("no-content response")
				return
			}

			// Skip if bid is empty
			if bid.IsEmpty() {
				return
			}

			// Getting the bid info will check if there are missing fields in the response
			bidInfo, err := parseBidInfo(bid)
			if err != nil {
				log.WithError(err).Warn("error parsing bid info")
				return
			}

			// Ignore bids with an empty block
			if bidInfo.blockHash == nilHash {
				log.Warn("relay responded with empty block hash")
				return
			}

			// Add some info about the bid to the logger
			valueEth := weiBigIntToEthBigFloat(bidInfo.value.ToBig())
			log = log.WithFields(logrus.Fields{
				"blockNumber": bidInfo.blockNumber,
				"blockHash":   bidInfo.blockHash.String(),
				"txRoot":      bidInfo.txRoot.String(),
				"value":       valueEth.Text('f', 18),
			})

			// Ensure the bid uses the correct public key
			if relay.PublicKey.String() != bidInfo.pubkey.String() {
				log.Errorf("bid pubkey mismatch. expected: %s - got: %s", relay.PublicKey.String(), bidInfo.pubkey.String())
				return
			}

			// Verify the relay signature in the relay response
			if !config.SkipRelaySignatureCheck {
				ok, err := checkRelaySignature(bid, m.builderSigningDomain, relay.PublicKey)
				if err != nil {
					log.WithError(err).Error("error verifying relay signature")
					return
				}
				if !ok {
					log.Error("failed to verify relay signature")
					return
				}
			}

			// Verify response coherence with proposer's input data
			if bidInfo.parentHash.String() != parentHashHex {
				log.WithFields(logrus.Fields{
					"originalParentHash": parentHashHex,
					"responseParentHash": bidInfo.parentHash.String(),
				}).Error("proposer and relay parent hashes are not the same")
				return
			}

			// Ignore bids with 0 value
			isZeroValue := bidInfo.value.IsZero()
			isEmptyListTxRoot := bidInfo.txRoot.String() == "0x7ffe241ea60187fdb0187bfa22de35d1f9bed7ab061d9401fd47e34a54fbede1"
			if isZeroValue || isEmptyListTxRoot {
				log.Warn("ignoring bid with 0 value")
				return
			}

			log.Debug("bid received")

			// Skip if value is lower than the minimum bid
			if bidInfo.value.CmpBig(m.relayMinBid.BigInt()) == -1 {
				log.Debug("ignoring bid below min-bid value")
				return
			}

			mu.Lock()
			defer mu.Unlock()

			// Remember which relays delivered which bids (multiple relays might deliver the top bid)
			relays[BlockHashHex(bidInfo.blockHash.String())] = append(relays[BlockHashHex(bidInfo.blockHash.String())], relay)

			// Compare the bid with already known top bid (if any)
			if !result.response.IsEmpty() {
				valueDiff := bidInfo.value.Cmp(result.bidInfo.value)
				if valueDiff == -1 {
					// The current bid is less profitable than already known one
					return
				} else if valueDiff == 0 {
					// The current bid is equally profitable as already known one
					// Use hash as tiebreaker
					previousBidBlockHash := result.bidInfo.blockHash
					if bidInfo.blockHash.String() >= previousBidBlockHash.String() {
						return
					}
				}
			}

			// Use this relay's response as mev-boost response because it's most profitable
			log.Debug("new best bid")
			result.response = *bid
			result.bidInfo = bidInfo
			result.t = time.Now()
		}(relay)
	}
	wg.Wait()

	// Set the winning relays before returning
	result.relays = relays[BlockHashHex(result.bidInfo.blockHash.String())]
	return result, nil
}

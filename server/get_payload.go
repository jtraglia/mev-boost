package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	builderApi "github.com/attestantio/go-builder-client/api"
	denebApi "github.com/attestantio/go-builder-client/api/deneb"
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
	"github.com/sirupsen/logrus"
)

var (
	errInvalidVersion      = errors.New("invalid version")
	errEmptyPayload        = errors.New("empty payload")
	errInvalidBlockHash    = errors.New("invalid block hash")
	errLengthsMismatch     = errors.New("blobs/commitments/proofs lengths mismatch")
	errCommitmentsMismatch = errors.New("commitments mismatch")
)

// getPayload requests the payload (execution payload, blobs bundle, etc) from the relays
func getPayload[P Payload](m *BoostService, log *logrus.Entry, ua UserAgent, blindedBlock P) (*builderApi.VersionedSubmitBlindedBlockResponse, bidResp) {
	var (
		slot      = getSlot(blindedBlock)
		blockHash = getBlockHash(blindedBlock)
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
	originalBid := m.bids[getBidKey(slot, blockHash)]
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
		if err := verifyBlobsBundle(log, response.Deneb.BlobsBundle, block.Message.Body.BlobKZGCommitments); err != nil {
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
		if err := verifyBlobsBundle(log, response.Electra.BlobsBundle, block.Message.Body.BlobKZGCommitments); err != nil {
			return err
		}
	}
	return nil
}

// verifyBlockHash checks that the block hash is correct
func verifyBlockHash[P Payload](log *logrus.Entry, payload P, executionPayloadHash phase0.Hash32) error {
	if getBlockHash(payload) != executionPayloadHash {
		log.WithFields(logrus.Fields{
			"responseBlockHash": executionPayloadHash.String(),
		}).Error("requestBlockHash does not equal responseBlockHash")
		return errInvalidBlockHash
	}
	return nil
}

// verifyBlobsBundle checks that blobs bundle is valid
func verifyBlobsBundle(log *logrus.Entry, blobs *denebApi.BlobsBundle, commitments []deneb.KZGCommitment) error {
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

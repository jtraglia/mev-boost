package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	builderApiV1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/flashbots/mev-boost/server/params"
	"github.com/flashbots/mev-boost/server/types"
	"github.com/sirupsen/logrus"
)

var errNoSuccessfulRelayResponse = errors.New("no successful relay response")

// registerValidator sends validator registrations to each relay
func (m *BoostService) registerValidator(log *logrus.Entry, ua UserAgent, validatorRegistrations []builderApiV1.SignedValidatorRegistration) error {
	headers := map[string]string{
		HeaderStartTimeUnixMS: fmt.Sprintf("%d", time.Now().UTC().UnixMilli()),
	}

	// Give relay the validator registrations
	respErrCh := make(chan error, len(m.relays))
	for _, relay := range m.relays {
		go func(relay types.RelayEntry) {
			url := relay.GetURI(params.PathRegisterValidator)
			log := log.WithField("url", url)

			_, err := SendHTTPRequest(context.Background(), m.httpClientRegVal, http.MethodPost, url, ua, headers, validatorRegistrations, nil)
			if err != nil {
				log.WithError(err).Warn("error calling registerValidator on relay")
			}
			respErrCh <- err
		}(relay)
	}

	go m.sendValidatorRegistrationsToRelayMonitors(validatorRegistrations)

	// Return success if any validator registration worked
	for range m.relays {
		respErr := <-respErrCh
		if respErr == nil {
			return nil
		}
	}

	return errNoSuccessfulRelayResponse
}

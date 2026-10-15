package a2a

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/calbebop/batesian/internal/attack"
)

type pushSetupObservation struct {
	best       setupObservation
	incomplete error
}

func (s *pushSetupObservation) observe(o setupObservation) {
	s.best.observe(o)
	if o.rank == setupOtherRefusal {
		s.incomplete = errors.Join(s.incomplete, fmt.Errorf("%w: %s", attack.ErrInconclusive, o.reason))
	}
}

func (s pushSetupObservation) err() error {
	return s.best.err()
}

func (s pushSetupObservation) partialErr() error {
	return s.incomplete
}

func pushReplyAccepted(resp *attack.Response, requestID string) bool {
	if resp == nil || !resp.IsSuccess() {
		return false
	}
	_, _, hasError, valid := discoveryResponse(resp.Body, requestID)
	return valid && !hasError
}

func pushTaskSetupOutcome(what, endpoint string, credentialed bool, resp *attack.Response, requestID string) setupObservation {
	if resp != nil && resp.IsSuccess() {
		_, _, _, valid := discoveryResponse(resp.Body, requestID)
		if !valid {
			return setupObservation{setupOtherRefusal, what + " reply did not match its request ID"}
		}
	}
	return classifyPushTaskSetup(what, endpoint, credentialed, resp)
}

func pushRegistrationOutcome(method string, resp *attack.Response, requestID string) setupObservation {
	if resp != nil && resp.IsSuccess() {
		_, _, _, valid := discoveryResponse(resp.Body, requestID)
		if !valid {
			return setupObservation{setupOtherRefusal, method + " reply did not match its request ID"}
		}
	}
	return classifyPushRegistration(method, resp)
}

func classifyPushTaskSetup(what, endpoint string, credentialed bool, resp *attack.Response) setupObservation {
	if resp != nil {
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
			return setupObservation{rank: setupFeatureAbsent}
		}
		if resp.IsAccepted() {
			var reply struct {
				Result struct {
					Kind string `json:"kind"`
				} `json:"result"`
			}
			if json.Unmarshal(resp.Body, &reply) == nil && reply.Result.Kind == "message" {
				return setupObservation{rank: setupFeatureAbsent}
			}
		}
	}
	return classifyTaskSetup(what, endpoint, credentialed, resp)
}

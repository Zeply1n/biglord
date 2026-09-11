package wire

import (
	"errors"
	"fmt"

	"github.com/vmihailenco/msgpack/v5"
)

// MaxEnvelopeBytes mirrors the websocket session read limit. DecodeEnvelope is
// also used during the enrollment handshake, so enforce the limit at the codec
// boundary rather than relying on every caller to configure its transport.
const MaxEnvelopeBytes = 8 * 1024 * 1024

func DecodeEnvelope(data []byte) (map[string]interface{}, error) {
	//garble:controlflow block_splits=10 junk_jumps=10 flatten_passes=2
	if len(data) == 0 {
		return nil, errors.New("empty MessagePack envelope")
	}
	if len(data) > MaxEnvelopeBytes {
		return nil, fmt.Errorf("MessagePack envelope exceeds %d byte limit", MaxEnvelopeBytes)
	}
	env := make(map[string]interface{})
	if err := msgpack.Unmarshal(data, &env); err != nil {
		return nil, err
	}
	return env, nil
}

// Package trigger combines several methods to trigger some  victim program behaviour under a common interface and
//allows to uniformly request a trigger via a URI
package trigger

//Allow calling code to construct Triggerer just by specifying an URI

import (
	"fmt"
	"net/url"
)

//Triggerer abstracts various ways to trigger soome victim code behaviour
type Triggerer interface {
	//Execute returns the result of the operation, if there is any or and error
	//If the underlying implementation makes an HTTP GET request the result
	//could could e.g. be the HTTP body.
	Execute() ([]byte, error)
}

//NewTriggerFromURI resolves the uri to a Triggerer. Returns an error
//if no Triggerer is known for the given uri
func NewTriggerFromURI(uri string) (Triggerer, error) {
	parsedURI, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URI : %v", err)
	}
	switch parsedURI.Scheme {
	case "http":
		fallthrough
	case "https":
		return NewHTTPTrigger(uri), nil
	case "ssh":
		return NewSSHTrigger(parsedURI.User.Username(), parsedURI.Host), nil
	default:
		return nil, fmt.Errorf("unsupported protocol %v", parsedURI.Scheme)
	}
}

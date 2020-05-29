// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// V1alpha1UserSignersResponse v1alpha1 user signers response
//
// swagger:model v1alpha1UserSignersResponse
type V1alpha1UserSignersResponse struct {

	// verification keys
	VerificationKeys []*V1alpha1VerificationKey `json:"verification_keys"`
}

// Validate validates this v1alpha1 user signers response
func (m *V1alpha1UserSignersResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateVerificationKeys(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *V1alpha1UserSignersResponse) validateVerificationKeys(formats strfmt.Registry) error {

	if swag.IsZero(m.VerificationKeys) { // not required
		return nil
	}

	for i := 0; i < len(m.VerificationKeys); i++ {
		if swag.IsZero(m.VerificationKeys[i]) { // not required
			continue
		}

		if m.VerificationKeys[i] != nil {
			if err := m.VerificationKeys[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("verification_keys" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *V1alpha1UserSignersResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *V1alpha1UserSignersResponse) UnmarshalBinary(b []byte) error {
	var res V1alpha1UserSignersResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
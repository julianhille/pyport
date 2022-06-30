import base64
import unittest
from typing import Dict

from jwt import DecodeError, InvalidSignatureError, InvalidTokenError
from parameterized import parameterized

from pyport import InvalidMXIDError, InvalidX5UError, Passport

# pylint: disable=protected-access


class _PassPort(unittest.TestCase):
    def setUp(self) -> None:
        self._private_key = b'''-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQglBnO+qn+RecAQ31T
jBklNu+AwiFN5eVHBFbnjecmMryhRANCAARGpVef6j7rMQ6lYSwbDkKwH7B3zM6P
G7S4BIamIY/7Bh9xzW6fIzFxK1sPNSNG45tjwNqVoIn38npSuRCRkG1n
-----END PRIVATE KEY-----'''
        self._public_key = b'''-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERqVXn+o+6zEOpWEsGw5CsB+wd8zO
jxu0uASGpiGP+wYfcc1unyMxcStbDzUjRuObY8DalaCJ9/J6UrkQkZBtZw==
-----END PUBLIC KEY-----'''


class TestPassPortValidation(_PassPort):
    """Test passport validation methods."""

    def test_validate_valid_mxuri(self) -> None:
        """Test that a valid mxuri does not throw."""
        entry = 'matrix:@user:sub.domain.tld'
        self.assertIsNone(Passport._validate_mxuri(entry))

    @parameterized.expand([
        # Missing schema
        ('noschema-user:sub.domain.tld',),
        # Wrong schema
        ('wrong-schema:user:sub.domain.tld',),
        # Missing user
        ('matrix::sub.domain.tld',),
        # Invalid domain
        ('matrix:user:sub!-no-vali_d-DOMAIN.com',),
        (None,),
        (12,),
    ])
    def test_validate_invalid_mxuri(self, entry: str) -> None:
        """Test that an invalid mxuri does throw an error."""
        self.assertRaises(Exception, Passport._validate_mxuri, entry)

    def test_validate_valid_mxid(self) -> None:
        """Test that a valid mxuri does not throw."""
        entry = '@user:sub.domain.tld'
        self.assertIsNone(Passport._validate_mxid(entry))

    @parameterized.expand([
        # Missing user
        (':sub.domain.tld',),
        # Missing a domain
        ('missing-domain:',),
        # With an invalid domain
        ('user:sub!-no-vali_d-DOMAIN.com',),
        (None,),
        (12,),
    ])
    def test_validate_invalid_mxid(self, entry: str) -> None:
        """Test that a valid mxid does throw an error."""
        self.assertRaises(InvalidMXIDError, Passport._validate_mxid, entry)

    @parameterized.expand([
        ({},),
        ('',),
        ({Passport.X5U: ''},),
        ({Passport.X5U: None},),
        # Wrong casing
        ({Passport.X5U.upper(): 'https://some-valid-domain-but-but-header.tld'},),
        # Invalid domain
        ({Passport.X5U: 'https://some-invalid-domain!.tld!_'},),
        (None,),
        (12,),
    ])
    def test_validate_invalid_x5u_header(self, header):
        """Test that invalid x5u header entries throw."""
        passport = Passport()
        self.assertRaises(
            InvalidX5UError,
            passport._validate_x5u, header)

    def test_validate_x5u_header(self):
        """Test valid x5u header."""
        passport = Passport()
        self.assertIsNone(passport._validate_x5u({'x5u': 'https://somedomain.tld'}))

    @parameterized.expand([
        ({'orig': {'uri': 'matrix:user:valid.tld'}, 'dest': {'uri': ['matrix:user:a.tld']}},),
        ({'orig': {'uri': 'matrix:user:valid.tld'}, 'dest': {'uri': ['matrix:user:b.tld', 'matrix:user12:a.tld']}},),
    ])
    def test_validate_valid_passport_claims(self, payload):
        """Test validation of passport claims."""
        passport = Passport()
        self.assertIsNone(passport._validate_passport_claims(payload))

    @parameterized.expand([
        ({'orig': {}, 'dest': {'uri': ['matrix:user:valid.tld']}},),
        ({'orig': {'uri': 'NOTVALID!.tld'}, 'dest': {'uri': ['matrix:user:valid.tld']}},),
        ({'orig': {'uri': 'matrix:user:valid.tld'}},),
        ({'orig': {'uri': 'matrix:user:valid.tld'}, 'dest': {}},),
        ({'orig': {'uri': 'matrix:user:valid.tld'}, 'dest': {'uri': []}},),
        ({'orig': {'uri': 'matrix:user:valid.tld'}, 'dest': {'uri': 'NOTVALID!.tld'}},),
        ({'orig': {'uri': 'matrix:user:valid.tld'}, 'dest': {'uri': ['NOTVALID!.tld']}},),
        ({'orig': {'uri': 'matrix:user:valid.tld'}, 'dest': {'uri': ['matrix:user:valid.tld', 'NOTVALID!.tld']}},),
        (None,),
        (12,),
    ])
    def test_validate_invalid_passport_claims(self, payload):
        """Test validation of invalid passport claims."""
        passport = Passport()
        self.assertRaises(InvalidTokenError, passport._validate_passport_claims, payload)


class TestPassportEncodeDecode(_PassPort):
    """Test encoding / decoding of the passport."""

    def setUp(self) -> None:
        """Set up a passport instance."""
        super().setUp()
        self.passport = Passport({'k': 'v'})

    def _encode(self) -> str:
        """Create a passport / jwt.

        Returns:
            String representation of a passport.

        """
        return self.passport.encode(
            'https://certurl.com',
            'user:wrong_domain.tld',
            'user:hostname.tld',
            self._private_key)

    @parameterized.expand([
        ({'dest_mxid': 'bad:domain.!tld'},  InvalidMXIDError),
        ({'origin_mxid': 'bad:domain.!tld'},  InvalidMXIDError),
        ({'key': 'SOMEBADKEY'}, ValueError),
        ({'cert_url': 'https://itsbad!.com/path.cert'},  InvalidX5UError),
    ])
    def test_encode_invalid_data(self, make_bad: Dict, expected_error: Exception):
        """Test encoding with an invalid field.

        Arguments:
            make_bad: dict to update valid data to make the data bad / wrong / raise exceptions
            expected_error: Expected error to be raised

        """
        data = {
            'cert_url': 'https://certurl.com',
            'dest_mxid': 'user:correct_domain.tld',
            'origin_mxid': 'user:hostname.tld',
            'key':  self._private_key
        }
        data.update(make_bad)
        self.assertRaises(expected_error, self.passport.encode, **data)

    def test_encode_valid(self):
        """Test valid encode of a passport."""
        self.assertIsInstance(
            self._encode(),
            str)

    def test_decode_valid(self):
        """Test encode -> decode a valid passport."""
        encoded = self._encode()
        self.assertIsInstance(
            self.passport.decode(encoded, key=self._public_key),
            dict)

    def test_decode_invalid_public_key(self):
        """Test decoding a valid passport with the wrong key throws an error."""
        encoded = self._encode()
        wrong_public_key = b'''-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8HNbQd/TmvCKwPKHkMF9fScavGeH
78YTU8qLS8I5HLHSSmlATLcslQMhNC/OhlWBYC626nIlo7XeebYS7Sb37g==
-----END PUBLIC KEY-----'''
        self.assertRaises(
            InvalidSignatureError,
            self.passport.decode, encoded, key=wrong_public_key)

    def test_decode_invalid_jwt(self):
        """Test invalid jwt does throw."""
        encoded = ''
        self.assertRaises(
            DecodeError,
            self.passport.decode, encoded, key=self._public_key)

    def test_encode_with_additional_headers(self):
        """Test encoding with additional header."""
        header_name = 'additional_header_to_search'
        result_encoded = self.passport.encode(
            'https://certurl.com',
            'user:wrong_domain.tld',
            'user:hostname.tld',
            self._private_key,
            headers={header_name: 'headers'})
        result = result_encoded.split('.')[0]
        result = base64.b64decode(result + '=' * len(result))
        self.assertIn(header_name.encode('utf-8'), result)


if __name__ == '__main__':
    unittest.main()

from venafi_codesigning_gitlab_integration import utils
import textwrap


def test_split_cert_chain():
    parts = utils.split_cert_chain(textwrap.dedent(
        """
        -----BEGIN CERTIFICATE-----
        aaa
        -----END CERTIFICATE-----
        -----BEGIN CERTIFICATE-----
        bbb
        -----END CERTIFICATE-----
        -----BEGIN CERTIFICATE-----
        ccc
        -----END CERTIFICATE-----
        """
    ).lstrip())

    assert len(parts) == 3
    assert parts[0] == textwrap.dedent(
        """
        -----BEGIN CERTIFICATE-----
        aaa
        -----END CERTIFICATE-----
        """
    ).lstrip()
    assert parts[1] == textwrap.dedent(
        """
        -----BEGIN CERTIFICATE-----
        bbb
        -----END CERTIFICATE-----
        """
    ).lstrip()
    assert parts[2] == textwrap.dedent(
        """
        -----BEGIN CERTIFICATE-----
        ccc
        -----END CERTIFICATE-----
        """
    ).lstrip()

import os

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEST_DATA = os.path.join(ROOT, "test_data")
PAKS = os.path.join(TEST_DATA, "paks")
EXPECTED = os.path.join(TEST_DATA, "expected")

#: Known-good conversions from the proven pipeline: pak -> {member: expected file}.
VECTORS = {
    "22765AJ13F.pak": {          # SH72531 engine ROM, 0x8000, denso_can
        "EB4I350A_r.sob": "EB4I350A-2016-CDM-Subaru-Legacy-2.5i-MT.hex",
    },
    "UD-S211B.pak": {            # multi-ROM, SH7058, 0x2000, denso
        "A2WC412D_j.sob": "A2WC412D-2005-USDM-Subaru-Forester-XT-AT.hex",
        "A2WC412I_j.sob": "A2WC412I-2005-USDM-Subaru-Forester-XT-MT.hex",
    },
    "82201AL30D.pak": {          # BIU module, module_biu_82201 key, 0xFF detect
        "DF105742_SKE_REPchg2.mot": "DF105742_SKE_REPchg2__82201AL30D.bin",
    },
}

#: In the archive but not a ROM: a flash writer, kernels, and small modules.
NON_ROM_MEMBERS = {
    "22611AG83D.pak": ["FW084000.MOT", "EGISBLJ2.sob", "EcuDataMap", "PcVerData"],
    "UD-S211B.pak": ["FW084000.MOT", "EGISBLJ0_7058.sob", "ETCCTLJ2.mot",
                     "AD3A104D.mot", "EcuDataMap", "PcVerData"],
}

requires_test_data = pytest.mark.skipif(
    not os.path.isdir(PAKS), reason="test_data/paks is not present in this checkout")


def pak_path(name):
    return os.path.join(PAKS, name)


def expected_bytes(name):
    with open(os.path.join(EXPECTED, name), "rb") as fh:
        return fh.read()


@pytest.fixture(scope="session")
def database():
    from subaru_pak import default_database
    return default_database()

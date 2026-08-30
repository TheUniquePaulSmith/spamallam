from app.tools import timezones


def test_catalogue_has_utc_and_all_names_valid():
    names = [name for name, _ in timezones.TIMEZONES]
    assert "UTC" in names
    assert "America/New_York" in names
    for name in names:
        assert timezones.is_valid(name)


def test_normalize_falls_back_to_utc():
    assert timezones.normalize("America/New_York") == "America/New_York"
    assert timezones.normalize("Mars/Olympus") == "UTC"
    assert timezones.normalize(None) == "UTC"
    assert timezones.normalize("") == "UTC"


def test_friendly_converts_utc_to_eastern():
    # 2026-01-15 18:30 UTC -> 13:30 EST (winter, UTC-5)
    out = timezones.friendly("2026-01-15T18:30:00+00:00", "America/New_York")
    assert "Jan 15, 2026 13:30" in out
    assert "EST" in out


def test_friendly_handles_dst():
    # July -> EDT (UTC-4)
    out = timezones.friendly("2026-07-15T18:30:00+00:00", "America/New_York")
    assert "14:30" in out
    assert "EDT" in out


def test_friendly_assumes_utc_for_naive_timestamp():
    out = timezones.friendly("2026-01-15T18:30:00", "UTC")
    assert "Jan 15, 2026 18:30" in out


def test_friendly_passthrough_on_garbage_and_unknown_zone():
    assert timezones.friendly("not-a-date", "UTC") == "not-a-date"
    assert timezones.friendly("", "UTC") == ""
    # unknown zone degrades to UTC rather than raising
    out = timezones.friendly("2026-01-15T18:30:00+00:00", "Mars/Olympus")
    assert "18:30" in out

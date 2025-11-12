import pandas as pd

from safeline_log_anal.analyzer import analyze_alerts, detect_malicious_payload


def test_detect_malicious_payload_identifies_sql_injection():
    malicious, signature, description = detect_malicious_payload("id=1 UNION SELECT password FROM users")
    assert malicious
    assert signature == "sql_union"
    assert "SQL" in (description or "")


def test_detect_malicious_payload_handles_url_encoding():
    payload = "q=%253Cscript%253Ealert(1)%253C%252Fscript%253E"
    malicious, signature, _ = detect_malicious_payload(payload)
    assert malicious
    assert signature == "xss_script" or signature == "xss_alert"


def test_analyze_alerts_marks_benign_entries():
    df = pd.DataFrame(
        {
            "payload": [
                "normal=1",
                "<script>alert('xss')</script>",
                "../../etc/passwd",
            ]
        }
    )

    annotated_df, benign_df = analyze_alerts(df)

    assert len(annotated_df) == 3
    assert annotated_df["analysis_is_malicious"].tolist() == [False, True, True]
    assert benign_df.shape[0] == 1
    assert benign_df.iloc[0]["payload"] == "normal=1"

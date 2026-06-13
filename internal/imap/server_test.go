package imap

import (
	"reflect"
	"testing"
)

func TestParseIMAPLinePreservesParenthesizedGroups(t *testing.T) {
	got := parseIMAPLine(`A001 FETCH 1:* (UID FLAGS BODY[])`)
	want := []string{"A001", "FETCH", "1:*", "(UID FLAGS BODY[])"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseIMAPLine mismatch:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestParseIMAPLinePreservesFlagGroups(t *testing.T) {
	got := parseIMAPLine(`A002 STORE 1,3 +FLAGS.SILENT (\Deleted \Seen)`)
	want := []string{"A002", "STORE", "1,3", "+FLAGS.SILENT", "(\\Deleted \\Seen)"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseIMAPLine mismatch:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestParseIMAPLineHandlesQuotedStringsAndEscapes(t *testing.T) {
	got := parseIMAPLine(`A003 LOGIN "alice@local.chat" "p\\a\"ss word"`)
	want := []string{"A003", "LOGIN", "alice@local.chat", `p\a"ss word`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseIMAPLine quoted mismatch:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestParseIMAPLinePreservesNonStandardQuotedBackslashes(t *testing.T) {
	got := parseIMAPLine(`A004 LOGIN "alice@local.chat" "pa\ss"`)
	want := []string{"A004", "LOGIN", "alice@local.chat", `pa\ss`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseIMAPLine should preserve non-standard quoted backslashes:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestSequenceSetMatchingSupportsCommasRangesAndReverseRanges(t *testing.T) {
	for _, seq := range []int{1, 3, 5, 6, 7, 10} {
		if !matchSeq(seq, 10, "1,3,7:5,*") {
			t.Fatalf("expected seq %d to match sequence set", seq)
		}
	}
	for _, seq := range []int{2, 4, 8, 9} {
		if matchSeq(seq, 10, "1,3,7:5,*") {
			t.Fatalf("expected seq %d not to match sequence set", seq)
		}
	}
}

func TestUIDSetMatchingSupportsCommasRangesAndWildcard(t *testing.T) {
	const maxUID uint32 = 100
	for _, uid := range []uint32{1, 3, 5, 6, 7, 100} {
		if !matchUID(uid, maxUID, "1,3,7:5,100:*") {
			t.Fatalf("expected UID %d to match UID set", uid)
		}
	}
	for _, uid := range []uint32{2, 4, 8, 99} {
		if matchUID(uid, maxUID, "1,3,7:5,100:*") {
			t.Fatalf("expected UID %d not to match UID set", uid)
		}
	}
}

func TestUIDWildcardMatchesOnlyHighestUID(t *testing.T) {
	if matchUID(99, 100, "*") {
		t.Fatalf("UID wildcard should not match non-highest UID")
	}
	if !matchUID(100, 100, "*") {
		t.Fatalf("UID wildcard should match highest UID")
	}
	if !matchUID(75, 100, "*:75") || !matchUID(100, 100, "*:75") || matchUID(74, 100, "*:75") {
		t.Fatalf("reverse wildcard UID range should match 75 through max UID")
	}
}

func TestParseStatusItemsIgnoresUnsupportedItemsAndNormalisesCase(t *testing.T) {
	got := parseStatusItems(`(messages UIDNEXT unseen X-UNKNOWN)`)
	for _, item := range []string{"MESSAGES", "UIDNEXT", "UNSEEN"} {
		if !got[item] {
			t.Fatalf("expected STATUS item %s to be requested", item)
		}
	}
	if got["X-UNKNOWN"] || got["RECENT"] || got["UIDVALIDITY"] {
		t.Fatalf("unexpected STATUS items parsed: %#v", got)
	}
}

func TestCleanAuthUsernameRejectsMalformedIMAPIdentities(t *testing.T) {
	cases := []string{
		"",
		"@local.chat",
		"alice@",
		"alice@@local.chat",
		"alice @local.chat",
		"alice@local.chat\r\n",
	}
	for _, tc := range cases {
		if got := cleanAuthUsername(tc); got != "" {
			t.Fatalf("cleanAuthUsername(%q) = %q, want empty string", tc, got)
		}
	}
	if got := cleanAuthUsername(" Alice@LOCAL.CHAT "); got != "alice@local.chat" {
		t.Fatalf("cleanAuthUsername normalisation failed: got %q", got)
	}
}

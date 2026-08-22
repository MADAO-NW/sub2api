package repository

import (
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

func TestQuotaFollowTimesAlignedIncludesFiveMinuteBoundary(t *testing.T) {
	start := time.Date(2026, 8, 21, 1, 0, 0, 0, time.UTC)
	if !quotaFollowTimesAligned([]time.Time{start.Add(5 * time.Minute), start}) {
		t.Fatal("exactly five minutes must be accepted")
	}
	if quotaFollowTimesAligned([]time.Time{start, start.Add(5*time.Minute + time.Second)}) {
		t.Fatal("more than five minutes must be rejected")
	}
}

func TestQuotaFollowMembershipHashIncludesMembershipTime(t *testing.T) {
	createdAt := time.Date(2026, 8, 21, 1, 0, 0, 0, time.UTC)
	members := []service.UserQuotaFollowProbeTarget{
		{AccountID: 2, MembershipSince: createdAt.Add(time.Minute)},
		{AccountID: 1, MembershipSince: createdAt},
	}
	first := quotaFollowMembershipHash(members)
	second := quotaFollowMembershipHash([]service.UserQuotaFollowProbeTarget{members[1], members[0]})
	if first != second {
		t.Fatal("member ordering must not change the hash")
	}
	members[0].MembershipSince = members[0].MembershipSince.Add(time.Second)
	if first == quotaFollowMembershipHash(members) {
		t.Fatal("membership time change must rotate the baseline hash")
	}
	members[0].MembershipSince = createdAt.Add(time.Minute)
	members[0].AccountType = "oauth"
	if first == quotaFollowMembershipHash(members) {
		t.Fatal("account type change must rotate the baseline hash")
	}
}

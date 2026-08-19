//go:build unit

package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type updateServiceCacheStub struct {
	data map[string]string
}

func (s *updateServiceCacheStub) GetUpdateInfo(_ context.Context, namespace string) (string, error) {
	if s.data == nil || s.data[namespace] == "" {
		return "", errors.New("cache miss")
	}
	return s.data[namespace], nil
}

func (s *updateServiceCacheStub) SetUpdateInfo(_ context.Context, namespace, data string, _ time.Duration) error {
	if s.data == nil {
		s.data = map[string]string{}
	}
	s.data[namespace] = data
	return nil
}

type updateServiceGitHubClientStub struct {
	release        *GitHubRelease
	recentReleases []*GitHubRelease
	recentErr      error
	latestRepos    []string
	recentRepos    []string
}

func (s *updateServiceGitHubClientStub) FetchLatestRelease(_ context.Context, repository string) (*GitHubRelease, error) {
	s.latestRepos = append(s.latestRepos, repository)
	return s.release, nil
}

func (s *updateServiceGitHubClientStub) FetchRecentReleases(_ context.Context, repository string, _ int) ([]*GitHubRelease, error) {
	s.recentRepos = append(s.recentRepos, repository)
	return s.recentReleases, s.recentErr
}

func (s *updateServiceGitHubClientStub) DownloadFile(context.Context, string, string, int64) error {
	panic("DownloadFile should not be called when no update is available")
}

func (s *updateServiceGitHubClientStub) FetchChecksumFile(context.Context, string) ([]byte, error) {
	panic("FetchChecksumFile should not be called when no update is available")
}

func TestUpdateServicePerformUpdateNoUpdateReturnsSentinel(t *testing.T) {
	svc := NewUpdateService(
		&updateServiceCacheStub{},
		&updateServiceGitHubClientStub{
			release: &GitHubRelease{
				TagName: "v0.1.132",
				Name:    "v0.1.132",
			},
		},
		"0.1.132",
		"release",
	)

	err := svc.PerformUpdate(context.Background())

	require.Error(t, err)
	require.True(t, errors.Is(err, ErrNoUpdateAvailable))
	require.ErrorIs(t, err, ErrNoUpdateAvailable)
}

func newRollbackTestService(current string, releases []*GitHubRelease) *UpdateService {
	return NewUpdateService(
		&updateServiceCacheStub{},
		&updateServiceGitHubClientStub{recentReleases: releases},
		current,
		"release",
	)
}

func TestUpdateServiceListRollbackVersionsFiltersAndCaps(t *testing.T) {
	releases := []*GitHubRelease{
		{TagName: "v0.1.148", PublishedAt: "2026-07-09T00:00:00Z"},                       // newer than current: excluded
		{TagName: "v0.1.147", PublishedAt: "2026-07-08T00:00:00Z"},                       // current: excluded
		{TagName: "v0.1.146-rc1", PublishedAt: "2026-07-07T12:00:00Z", Prerelease: true}, // prerelease: excluded
		{TagName: "v0.1.146", PublishedAt: "2026-07-07T00:00:00Z"},
		{TagName: "v0.1.145", PublishedAt: "2026-07-06T00:00:00Z", Draft: true}, // draft: excluded
		{TagName: "v0.1.144", PublishedAt: "2026-07-05T00:00:00Z"},
		{TagName: "v0.1.144", PublishedAt: "2026-07-05T00:00:00Z"}, // duplicate: excluded
		{TagName: "v0.1.143", PublishedAt: "2026-07-04T00:00:00Z"},
		{TagName: "v0.1.142", PublishedAt: "2026-07-03T00:00:00Z"}, // beyond cap of 3: excluded
	}
	svc := newRollbackTestService("0.1.147", releases)

	versions, err := svc.ListRollbackVersions(context.Background())

	require.NoError(t, err)
	require.Len(t, versions, 3)
	require.Equal(t, "0.1.146", versions[0].Version)
	require.Equal(t, "0.1.144", versions[1].Version)
	require.Equal(t, "0.1.143", versions[2].Version)
}

func TestUpdateServiceListRollbackVersionsSortsUnorderedInput(t *testing.T) {
	releases := []*GitHubRelease{
		{TagName: "v0.1.144"},
		{TagName: "v0.1.146"},
		{TagName: "v0.1.145"},
	}
	svc := newRollbackTestService("0.1.147", releases)

	versions, err := svc.ListRollbackVersions(context.Background())

	require.NoError(t, err)
	require.Len(t, versions, 3)
	require.Equal(t, "0.1.146", versions[0].Version)
	require.Equal(t, "0.1.145", versions[1].Version)
	require.Equal(t, "0.1.144", versions[2].Version)
}

func TestUpdateServiceListRollbackVersionsEmptyWhenNoneOlder(t *testing.T) {
	releases := []*GitHubRelease{
		{TagName: "v0.1.147"},
		{TagName: "v0.1.148"},
	}
	svc := newRollbackTestService("0.1.147", releases)

	versions, err := svc.ListRollbackVersions(context.Background())

	require.NoError(t, err)
	require.Empty(t, versions)
}

func TestUpdateServiceListRollbackVersionsPropagatesFetchError(t *testing.T) {
	svc := NewUpdateService(
		&updateServiceCacheStub{},
		&updateServiceGitHubClientStub{recentErr: errors.New("github unavailable")},
		"0.1.147",
		"release",
	)

	_, err := svc.ListRollbackVersions(context.Background())

	require.Error(t, err)
	require.Contains(t, err.Error(), "github unavailable")
}

func TestUpdateServiceRollbackToVersionRejectsDisallowedTargets(t *testing.T) {
	releases := []*GitHubRelease{
		{TagName: "v0.1.148"},
		{TagName: "v0.1.147"},
		{TagName: "v0.1.146"},
		{TagName: "v0.1.145"},
		{TagName: "v0.1.144"},
		{TagName: "v0.1.143"},
		{TagName: "v0.1.142"},
	}
	svc := newRollbackTestService("0.1.147", releases)

	for _, target := range []string{
		"",         // empty
		"0.1.147",  // current version
		"v0.1.147", // current version with prefix
		"0.1.148",  // newer than current
		"0.1.142",  // older than the 3 most recent
		"9.9.9",    // nonexistent
	} {
		err := svc.RollbackToVersion(context.Background(), target)
		require.ErrorIs(t, err, ErrRollbackVersionNotAllowed, "target %q should be rejected", target)
	}
}

func TestUpdateServiceRollbackToVersionAcceptsVPrefix(t *testing.T) {
	// No platform asset in the release: the target passes the allowlist check
	// and fails later at asset lookup, proving the version itself was accepted.
	releases := []*GitHubRelease{
		{TagName: "v0.1.147"},
		{TagName: "v0.1.146"},
	}
	svc := newRollbackTestService("0.1.147", releases)

	err := svc.RollbackToVersion(context.Background(), "v0.1.146")

	require.Error(t, err)
	require.NotErrorIs(t, err, ErrRollbackVersionNotAllowed)
	require.Contains(t, err.Error(), "no compatible release found")
}

func TestUpdateServiceInvalidConfiguredRepositoryDisablesWithoutOfficialFallback(t *testing.T) {
	client := &updateServiceGitHubClientStub{}
	svc := NewUpdateService(
		&updateServiceCacheStub{},
		client,
		"1.2.3",
		"release",
		"invalid/repo/extra",
		"stable",
	)

	info, err := svc.CheckUpdate(context.Background(), true)

	require.NoError(t, err)
	require.False(t, info.HasUpdate)
	require.Contains(t, info.Warning, "online update disabled")
	require.Equal(t, "invalid", info.UpdateRepository)
	require.Empty(t, client.latestRepos)
	require.Empty(t, client.recentRepos)
	require.ErrorIs(t, svc.PerformUpdate(context.Background()), ErrOnlineUpdateDisabled)
}

func TestUpdateServiceCustomPrereleaseChannelUsesRecentMatchingReleases(t *testing.T) {
	client := &updateServiceGitHubClientStub{recentReleases: []*GitHubRelease{
		{TagName: "v1.2.3-audit.2", Name: "audit 2", Prerelease: true},
		{TagName: "v1.2.3-beta.99", Name: "beta", Prerelease: true},
		{TagName: "v1.2.4", Name: "stable"},
		{TagName: "v1.2.3-audit.10", Name: "audit 10", Prerelease: true},
		{TagName: "v1.2.3-audit.11", Name: "draft", Prerelease: true, Draft: true},
	}}
	svc := NewUpdateService(
		&updateServiceCacheStub{},
		client,
		"1.2.3-audit.1",
		"release",
		"example/sub2api",
		"",
	)

	info, err := svc.CheckUpdate(context.Background(), true)

	require.NoError(t, err)
	require.True(t, info.HasUpdate)
	require.Equal(t, "1.2.3-audit.10", info.LatestVersion)
	require.Equal(t, "example/sub2api", info.UpdateRepository)
	require.Equal(t, "audit", info.UpdateChannel)
	require.Empty(t, client.latestRepos, "prerelease channels must not use /releases/latest")
	require.Equal(t, []string{"example/sub2api"}, client.recentRepos)
}

func TestUpdateServiceStableCustomRepositoryAndCacheNamespace(t *testing.T) {
	cache := &updateServiceCacheStub{}
	client := &updateServiceGitHubClientStub{release: &GitHubRelease{TagName: "v1.2.4", Name: "stable"}}
	svc := NewUpdateService(cache, client, "1.2.3", "release", "example/sub2api", "stable")

	first, err := svc.CheckUpdate(context.Background(), true)
	require.NoError(t, err)
	require.True(t, first.HasUpdate)
	require.Equal(t, []string{"example/sub2api"}, client.latestRepos)
	require.Contains(t, cache.data, "example:sub2api:stable")

	cached, err := svc.CheckUpdate(context.Background(), false)
	require.NoError(t, err)
	require.True(t, cached.Cached)
	require.Equal(t, "example/sub2api", cached.UpdateRepository)
	require.Equal(t, "stable", cached.UpdateChannel)
}

func TestCompareVersionsUsesSemverPrereleasePrecedence(t *testing.T) {
	require.Less(t, compareVersions("1.2.3-audit.2", "1.2.3-audit.10"), 0)
	require.Less(t, compareVersions("1.2.3-rc.1", "1.2.3"), 0)
	require.Greater(t, compareVersions("1.2.4-audit.1", "1.2.3-audit.99"), 0)
	require.Equal(t, 0, compareVersions("1.2.3+build.1", "1.2.3+build.2"))
}

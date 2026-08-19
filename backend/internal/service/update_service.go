package service

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

var (
	ErrNoUpdateAvailable         = infraerrors.Conflict("ALREADY_UP_TO_DATE", "no update available; current version is latest")
	ErrRollbackVersionNotAllowed = infraerrors.BadRequest("ROLLBACK_VERSION_NOT_ALLOWED", "version is not in the allowed rollback list")
	ErrOnlineUpdateDisabled      = infraerrors.Conflict("ONLINE_UPDATE_DISABLED", "online update is disabled by invalid build-time update source")
)

const (
	updateCacheTTL     = 1200 // 20 minutes
	officialGitHubRepo = "Wei-Shaw/sub2api"

	// Security: allowed download domains for updates
	allowedDownloadHost = "github.com"
	allowedAssetHost    = "objects.githubusercontent.com"

	// Security: max download size (500MB)
	maxDownloadSize = 500 * 1024 * 1024

	// Rollback: expose at most the 3 most recent versions older than current
	maxRollbackVersions = 3
	// Fetch a few extra releases so filtering (current/newer/prerelease) still leaves enough candidates
	rollbackFetchPageSize = 15
)

// UpdateCache defines cache operations for update service
type UpdateCache interface {
	GetUpdateInfo(ctx context.Context, namespace string) (string, error)
	SetUpdateInfo(ctx context.Context, namespace, data string, ttl time.Duration) error
}

// GitHubReleaseClient 获取 GitHub release 信息的接口
type GitHubReleaseClient interface {
	FetchLatestRelease(ctx context.Context, repo string) (*GitHubRelease, error)
	FetchRecentReleases(ctx context.Context, repo string, perPage int) ([]*GitHubRelease, error)
	DownloadFile(ctx context.Context, url, dest string, maxSize int64) error
	FetchChecksumFile(ctx context.Context, url string) ([]byte, error)
}

// UpdateService handles software updates
type UpdateService struct {
	cache            UpdateCache
	githubClient     GitHubReleaseClient
	currentVersion   string
	buildType        string // "source" for manual builds, "release" for CI builds
	updateRepository string
	updateChannel    string
	updateCacheKey   string
	sourceWarning    string
}

// NewUpdateService creates a new UpdateService
func NewUpdateService(
	cache UpdateCache,
	githubClient GitHubReleaseClient,
	version, buildType string,
	updateSource ...string,
) *UpdateService {
	repository := ""
	channel := ""
	if len(updateSource) > 0 {
		repository = updateSource[0]
	}
	if len(updateSource) > 1 {
		channel = updateSource[1]
	}
	repository, channel, warning := resolveUpdateSource(version, repository, channel)
	return &UpdateService{
		cache:            cache,
		githubClient:     githubClient,
		currentVersion:   version,
		buildType:        buildType,
		updateRepository: repository,
		updateChannel:    channel,
		updateCacheKey:   updateCacheNamespace(repository, channel),
		sourceWarning:    warning,
	}
}

// UpdateInfo contains update information
type UpdateInfo struct {
	CurrentVersion   string       `json:"current_version"`
	LatestVersion    string       `json:"latest_version"`
	HasUpdate        bool         `json:"has_update"`
	ReleaseInfo      *ReleaseInfo `json:"release_info,omitempty"`
	Cached           bool         `json:"cached"`
	Warning          string       `json:"warning,omitempty"`
	BuildType        string       `json:"build_type"` // "source" or "release"
	UpdateRepository string       `json:"update_repository"`
	UpdateChannel    string       `json:"update_channel"`
}

// ReleaseInfo contains GitHub release details
type ReleaseInfo struct {
	Name        string  `json:"name"`
	Body        string  `json:"body"`
	PublishedAt string  `json:"published_at"`
	HTMLURL     string  `json:"html_url"`
	Assets      []Asset `json:"assets,omitempty"`
}

// Asset represents a release asset
type Asset struct {
	Name        string `json:"name"`
	DownloadURL string `json:"download_url"`
	Size        int64  `json:"size"`
}

// GitHubRelease represents GitHub API response
type GitHubRelease struct {
	TagName     string        `json:"tag_name"`
	Name        string        `json:"name"`
	Body        string        `json:"body"`
	PublishedAt string        `json:"published_at"`
	HTMLURL     string        `json:"html_url"`
	Draft       bool          `json:"draft"`
	Prerelease  bool          `json:"prerelease"`
	Assets      []GitHubAsset `json:"assets"`
}

// RollbackVersion describes a release version the system can roll back to
type RollbackVersion struct {
	Version     string `json:"version"` // without "v" prefix, e.g. "0.1.146"
	PublishedAt string `json:"published_at"`
	HTMLURL     string `json:"html_url"`
}

type GitHubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

// CheckUpdate checks for available updates
func (s *UpdateService) CheckUpdate(ctx context.Context, force bool) (*UpdateInfo, error) {
	if s.sourceWarning != "" {
		return &UpdateInfo{
			CurrentVersion:   s.currentVersion,
			LatestVersion:    s.currentVersion,
			HasUpdate:        false,
			Warning:          s.sourceWarning,
			BuildType:        s.buildType,
			UpdateRepository: s.updateRepository,
			UpdateChannel:    s.updateChannel,
		}, nil
	}
	// Try cache first
	if !force {
		if cached, err := s.getFromCache(ctx); err == nil && cached != nil {
			return cached, nil
		}
	}

	// Fetch from GitHub
	info, err := s.fetchLatestRelease(ctx)
	if err != nil {
		// Return cached on error
		if cached, cacheErr := s.getFromCache(ctx); cacheErr == nil && cached != nil {
			cached.Warning = "Using cached data: " + err.Error()
			return cached, nil
		}
		return &UpdateInfo{
			CurrentVersion:   s.currentVersion,
			LatestVersion:    s.currentVersion,
			HasUpdate:        false,
			Warning:          err.Error(),
			BuildType:        s.buildType,
			UpdateRepository: s.updateRepository,
			UpdateChannel:    s.updateChannel,
		}, nil
	}

	// Cache result
	s.saveToCache(ctx, info)
	return info, nil
}

// PerformUpdate downloads and applies the update
// Uses atomic file replacement pattern for safe in-place updates
func (s *UpdateService) PerformUpdate(ctx context.Context) error {
	if s.sourceWarning != "" {
		return ErrOnlineUpdateDisabled
	}
	info, err := s.CheckUpdate(ctx, true)
	if err != nil {
		return err
	}

	if !info.HasUpdate {
		return ErrNoUpdateAvailable
	}

	return s.applyReleaseAssets(ctx, info.ReleaseInfo.Assets)
}

// applyReleaseAssets downloads the platform archive from the given release assets,
// verifies its checksum, and atomically swaps the running binary.
// Shared by PerformUpdate (latest) and RollbackToVersion (specific older version).
func (s *UpdateService) applyReleaseAssets(ctx context.Context, releaseAssets []Asset) error {
	// Find matching archive and checksum for current platform
	archiveName := s.getArchiveName()
	var downloadURL string
	var checksumURL string

	for _, asset := range releaseAssets {
		if strings.Contains(asset.Name, archiveName) && !strings.HasSuffix(asset.Name, ".txt") {
			downloadURL = asset.DownloadURL
		}
		if asset.Name == "checksums.txt" {
			checksumURL = asset.DownloadURL
		}
	}

	if downloadURL == "" {
		return fmt.Errorf("no compatible release found for %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	// SECURITY: Validate download URL is from trusted domain
	if err := validateDownloadURL(downloadURL); err != nil {
		return fmt.Errorf("invalid download URL: %w", err)
	}
	if checksumURL != "" {
		if err := validateDownloadURL(checksumURL); err != nil {
			return fmt.Errorf("invalid checksum URL: %w", err)
		}
	}

	// Get current executable path
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return fmt.Errorf("failed to resolve symlinks: %w", err)
	}

	exeDir := filepath.Dir(exePath)

	// Create temp directory in the SAME directory as executable
	// This ensures os.Rename is atomic (same filesystem)
	tempDir, err := os.MkdirTemp(exeDir, ".sub2api-update-*")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	// Download archive
	archivePath := filepath.Join(tempDir, filepath.Base(downloadURL))
	if err := s.downloadFile(ctx, downloadURL, archivePath); err != nil {
		return fmt.Errorf("download failed: %w", err)
	}

	// Verify checksum if available
	if checksumURL != "" {
		if err := s.verifyChecksum(ctx, archivePath, checksumURL); err != nil {
			return fmt.Errorf("checksum verification failed: %w", err)
		}
	}

	// Extract binary from archive
	newBinaryPath := filepath.Join(tempDir, "sub2api")
	if err := s.extractBinary(archivePath, newBinaryPath); err != nil {
		return fmt.Errorf("extraction failed: %w", err)
	}

	// Set executable permission before replacement
	if err := os.Chmod(newBinaryPath, 0755); err != nil {
		return fmt.Errorf("chmod failed: %w", err)
	}

	// Atomic replacement using rename pattern:
	// 1. Rename current -> backup (atomic on Unix)
	// 2. Rename new -> current (atomic on Unix, same filesystem)
	// If step 2 fails, restore backup
	backupPath := exePath + ".backup"

	// Remove old backup if exists
	_ = os.Remove(backupPath)

	// Step 1: Move current binary to backup
	if err := os.Rename(exePath, backupPath); err != nil {
		return fmt.Errorf("backup failed: %w", err)
	}

	// Step 2: Move new binary to target location (atomic, same filesystem)
	if err := os.Rename(newBinaryPath, exePath); err != nil {
		// Restore backup on failure
		if restoreErr := os.Rename(backupPath, exePath); restoreErr != nil {
			return fmt.Errorf("replace failed and restore failed: %w (restore error: %v)", err, restoreErr)
		}
		return fmt.Errorf("replace failed (restored backup): %w", err)
	}

	// Success - backup file is kept for rollback capability
	// It will be cleaned up on next successful update
	return nil
}

// Rollback restores the previous version
func (s *UpdateService) Rollback() error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return fmt.Errorf("failed to resolve symlinks: %w", err)
	}

	backupFile := exePath + ".backup"
	if _, err := os.Stat(backupFile); os.IsNotExist(err) {
		return fmt.Errorf("no backup found")
	}

	// Replace current with backup
	if err := os.Rename(backupFile, exePath); err != nil {
		return fmt.Errorf("rollback failed: %w", err)
	}

	return nil
}

// ListRollbackVersions returns up to maxRollbackVersions release versions that are
// strictly older than the current version (the current version itself is excluded),
// newest first. Draft and prerelease entries are skipped.
func (s *UpdateService) ListRollbackVersions(ctx context.Context) ([]RollbackVersion, error) {
	if s.sourceWarning != "" {
		return nil, ErrOnlineUpdateDisabled
	}
	releases, err := s.fetchRollbackCandidates(ctx)
	if err != nil {
		return nil, err
	}

	versions := make([]RollbackVersion, 0, len(releases))
	for _, r := range releases {
		versions = append(versions, RollbackVersion{
			Version:     strings.TrimPrefix(r.TagName, "v"),
			PublishedAt: r.PublishedAt,
			HTMLURL:     r.HTMLURL,
		})
	}
	return versions, nil
}

// RollbackToVersion downloads and installs a specific older version.
// The target must be one of the versions returned by ListRollbackVersions;
// anything else (including the current version) is rejected.
func (s *UpdateService) RollbackToVersion(ctx context.Context, version string) error {
	if s.sourceWarning != "" {
		return ErrOnlineUpdateDisabled
	}
	target := strings.TrimPrefix(strings.TrimSpace(version), "v")
	if target == "" {
		return ErrRollbackVersionNotAllowed
	}

	releases, err := s.fetchRollbackCandidates(ctx)
	if err != nil {
		return err
	}

	var match *GitHubRelease
	for _, r := range releases {
		if strings.TrimPrefix(r.TagName, "v") == target {
			match = r
			break
		}
	}
	if match == nil {
		return ErrRollbackVersionNotAllowed
	}

	assets := make([]Asset, len(match.Assets))
	for i, a := range match.Assets {
		assets[i] = Asset{
			Name:        a.Name,
			DownloadURL: a.BrowserDownloadURL,
			Size:        a.Size,
		}
	}

	return s.applyReleaseAssets(ctx, assets)
}

// fetchRollbackCandidates fetches recent releases and keeps the newest
// maxRollbackVersions entries strictly older than the current version.
func (s *UpdateService) fetchRollbackCandidates(ctx context.Context) ([]*GitHubRelease, error) {
	releases, err := s.githubClient.FetchRecentReleases(ctx, s.updateRepository, rollbackFetchPageSize)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]bool, len(releases))
	candidates := make([]*GitHubRelease, 0, maxRollbackVersions)
	for _, r := range releases {
		if r == nil || r.Draft || !releaseMatchesUpdateChannel(r, s.updateChannel) {
			continue
		}
		v := strings.TrimPrefix(r.TagName, "v")
		if v == "" || seen[v] {
			continue
		}
		// Only versions strictly older than current (also excludes current itself)
		if compareVersions(v, s.currentVersion) >= 0 {
			continue
		}
		seen[v] = true
		candidates = append(candidates, r)
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		return compareVersions(
			strings.TrimPrefix(candidates[i].TagName, "v"),
			strings.TrimPrefix(candidates[j].TagName, "v"),
		) > 0
	})

	if len(candidates) > maxRollbackVersions {
		candidates = candidates[:maxRollbackVersions]
	}
	return candidates, nil
}

func (s *UpdateService) fetchLatestRelease(ctx context.Context) (*UpdateInfo, error) {
	release, err := s.fetchLatestReleaseForChannel(ctx)
	if err != nil {
		return nil, err
	}

	latestVersion := strings.TrimPrefix(release.TagName, "v")

	assets := make([]Asset, len(release.Assets))
	for i, a := range release.Assets {
		assets[i] = Asset{
			Name:        a.Name,
			DownloadURL: a.BrowserDownloadURL,
			Size:        a.Size,
		}
	}

	return &UpdateInfo{
		CurrentVersion:   s.currentVersion,
		LatestVersion:    latestVersion,
		HasUpdate:        compareVersions(s.currentVersion, latestVersion) < 0,
		UpdateRepository: s.updateRepository,
		UpdateChannel:    s.updateChannel,
		ReleaseInfo: &ReleaseInfo{
			Name:        release.Name,
			Body:        release.Body,
			PublishedAt: release.PublishedAt,
			HTMLURL:     release.HTMLURL,
			Assets:      assets,
		},
		Cached:    false,
		BuildType: s.buildType,
	}, nil
}

func (s *UpdateService) fetchLatestReleaseForChannel(ctx context.Context) (*GitHubRelease, error) {
	if s.updateChannel == "stable" {
		release, err := s.githubClient.FetchLatestRelease(ctx, s.updateRepository)
		if err != nil {
			return nil, err
		}
		if release == nil || release.Draft || !releaseMatchesUpdateChannel(release, s.updateChannel) {
			return nil, fmt.Errorf("latest release does not match stable update channel")
		}
		return release, nil
	}
	releases, err := s.githubClient.FetchRecentReleases(ctx, s.updateRepository, 100)
	if err != nil {
		return nil, err
	}
	var latest *GitHubRelease
	for _, release := range releases {
		if release == nil || release.Draft || !releaseMatchesUpdateChannel(release, s.updateChannel) {
			continue
		}
		if latest == nil || compareVersions(
			strings.TrimPrefix(latest.TagName, "v"),
			strings.TrimPrefix(release.TagName, "v"),
		) < 0 {
			latest = release
		}
	}
	if latest == nil {
		return nil, fmt.Errorf("no release found for update channel %s", s.updateChannel)
	}
	return latest, nil
}

func (s *UpdateService) downloadFile(ctx context.Context, downloadURL, dest string) error {
	return s.githubClient.DownloadFile(ctx, downloadURL, dest, maxDownloadSize)
}

func (s *UpdateService) getArchiveName() string {
	osName := runtime.GOOS
	arch := runtime.GOARCH
	return fmt.Sprintf("%s_%s", osName, arch)
}

// validateDownloadURL checks if the URL is from an allowed domain
// SECURITY: This prevents SSRF and ensures downloads only come from trusted GitHub domains
func validateDownloadURL(rawURL string) error {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	// Must be HTTPS
	if parsedURL.Scheme != "https" {
		return fmt.Errorf("only HTTPS URLs are allowed")
	}

	// Check against allowed hosts
	host := parsedURL.Host
	// GitHub release URLs can be from github.com or objects.githubusercontent.com
	if host != allowedDownloadHost &&
		!strings.HasSuffix(host, "."+allowedDownloadHost) &&
		host != allowedAssetHost &&
		!strings.HasSuffix(host, "."+allowedAssetHost) {
		return fmt.Errorf("download from untrusted host: %s", host)
	}

	return nil
}

func (s *UpdateService) verifyChecksum(ctx context.Context, filePath, checksumURL string) error {
	// Download checksums file
	checksumData, err := s.githubClient.FetchChecksumFile(ctx, checksumURL)
	if err != nil {
		return fmt.Errorf("failed to download checksums: %w", err)
	}

	// Calculate file hash
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	actualHash := hex.EncodeToString(h.Sum(nil))

	// Find expected hash in checksums file
	fileName := filepath.Base(filePath)
	scanner := bufio.NewScanner(strings.NewReader(string(checksumData)))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) == 2 && parts[1] == fileName {
			if parts[0] == actualHash {
				return nil
			}
			return fmt.Errorf("checksum mismatch: expected %s, got %s", parts[0], actualHash)
		}
	}

	return fmt.Errorf("checksum not found for %s", fileName)
}

func (s *UpdateService) extractBinary(archivePath, destPath string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	var reader io.Reader = f

	// Handle gzip compression
	if strings.HasSuffix(archivePath, ".gz") || strings.HasSuffix(archivePath, ".tar.gz") || strings.HasSuffix(archivePath, ".tgz") {
		gzr, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer func() { _ = gzr.Close() }()
		reader = gzr
	}

	// Handle tar archive
	if strings.Contains(archivePath, ".tar") {
		tr := tar.NewReader(reader)
		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}

			// SECURITY: Prevent Zip Slip / Path Traversal attack
			// Only allow files with safe base names, no directory traversal
			baseName := filepath.Base(hdr.Name)

			// Check for path traversal attempts
			if strings.Contains(hdr.Name, "..") {
				return fmt.Errorf("path traversal attempt detected: %s", hdr.Name)
			}

			// Validate the entry is a regular file
			if hdr.Typeflag != tar.TypeReg {
				continue // Skip directories and special files
			}

			// Only extract the specific binary we need
			if baseName == "sub2api" || baseName == "sub2api.exe" {
				// Additional security: limit file size (max 500MB)
				const maxBinarySize = 500 * 1024 * 1024
				if hdr.Size > maxBinarySize {
					return fmt.Errorf("binary too large: %d bytes (max %d)", hdr.Size, maxBinarySize)
				}

				out, err := os.Create(destPath)
				if err != nil {
					return err
				}

				// Use LimitReader to prevent decompression bombs
				limited := io.LimitReader(tr, maxBinarySize)
				if _, err := io.Copy(out, limited); err != nil {
					_ = out.Close()
					return err
				}
				if err := out.Close(); err != nil {
					return err
				}
				return nil
			}
		}
		return fmt.Errorf("binary not found in archive")
	}

	// Direct copy for non-tar files (with size limit)
	const maxBinarySize = 500 * 1024 * 1024
	out, err := os.Create(destPath)
	if err != nil {
		return err
	}

	limited := io.LimitReader(reader, maxBinarySize)
	if _, err := io.Copy(out, limited); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func (s *UpdateService) getFromCache(ctx context.Context) (*UpdateInfo, error) {
	data, err := s.cache.GetUpdateInfo(ctx, s.updateCacheKey)
	if err != nil {
		return nil, err
	}

	var cached struct {
		Latest      string       `json:"latest"`
		ReleaseInfo *ReleaseInfo `json:"release_info"`
		Timestamp   int64        `json:"timestamp"`
	}
	if err := json.Unmarshal([]byte(data), &cached); err != nil {
		return nil, err
	}

	if time.Now().Unix()-cached.Timestamp > updateCacheTTL {
		return nil, fmt.Errorf("cache expired")
	}

	return &UpdateInfo{
		CurrentVersion:   s.currentVersion,
		LatestVersion:    cached.Latest,
		HasUpdate:        compareVersions(s.currentVersion, cached.Latest) < 0,
		ReleaseInfo:      cached.ReleaseInfo,
		Cached:           true,
		BuildType:        s.buildType,
		UpdateRepository: s.updateRepository,
		UpdateChannel:    s.updateChannel,
	}, nil
}

func (s *UpdateService) saveToCache(ctx context.Context, info *UpdateInfo) {
	cacheData := struct {
		Latest      string       `json:"latest"`
		ReleaseInfo *ReleaseInfo `json:"release_info"`
		Timestamp   int64        `json:"timestamp"`
	}{
		Latest:      info.LatestVersion,
		ReleaseInfo: info.ReleaseInfo,
		Timestamp:   time.Now().Unix(),
	}

	data, _ := json.Marshal(cacheData)
	_ = s.cache.SetUpdateInfo(ctx, s.updateCacheKey, string(data), time.Duration(updateCacheTTL)*time.Second)
}

type semanticVersion struct {
	core       [3]int
	prerelease []string
}

func resolveUpdateSource(version, configuredRepository, configuredChannel string) (string, string, string) {
	repository := strings.TrimSpace(configuredRepository)
	if repository == "" {
		repository = officialGitHubRepo
	} else if !validGitHubRepository(repository) {
		return "invalid", "disabled", "online update disabled: invalid build-time update repository"
	}
	channel := strings.TrimSpace(configuredChannel)
	if channel == "" {
		channel = updateChannelFromVersion(version)
	}
	if channel != "stable" && !validPrereleaseIdentifier(channel) {
		return repository, "disabled", "online update disabled: invalid build-time update channel"
	}
	return repository, channel, ""
}

func validGitHubRepository(repository string) bool {
	if len(repository) > 200 || strings.Count(repository, "/") != 1 {
		return false
	}
	parts := strings.Split(repository, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return false
		}
		for _, char := range part {
			if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
				(char >= '0' && char <= '9') || char == '-' || char == '_' || char == '.' {
				continue
			}
			return false
		}
	}
	return true
}

func validPrereleaseIdentifier(channel string) bool {
	if channel == "" || len(channel) > 64 {
		return false
	}
	for _, char := range channel {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '-' {
			continue
		}
		return false
	}
	return true
}

func updateChannelFromVersion(version string) string {
	parsed, ok := parseSemanticVersion(version)
	if !ok || len(parsed.prerelease) == 0 {
		return "stable"
	}
	return parsed.prerelease[0]
}

func updateCacheNamespace(repository, channel string) string {
	return strings.ReplaceAll(repository, "/", ":") + ":" + channel
}

func releaseMatchesUpdateChannel(release *GitHubRelease, channel string) bool {
	if release == nil {
		return false
	}
	version, ok := parseSemanticVersion(release.TagName)
	if !ok {
		return false
	}
	if channel == "stable" {
		return !release.Prerelease && len(version.prerelease) == 0
	}
	return release.Prerelease && len(version.prerelease) > 0 && version.prerelease[0] == channel
}

// compareVersions 按 SemVer 规则比较版本，并处理预发布版本优先级。
func compareVersions(current, latest string) int {
	currentVersion, currentOK := parseSemanticVersion(current)
	latestVersion, latestOK := parseSemanticVersion(latest)
	if !currentOK || !latestOK {
		return compareLooseVersionCore(current, latest)
	}
	for index := range currentVersion.core {
		if currentVersion.core[index] < latestVersion.core[index] {
			return -1
		}
		if currentVersion.core[index] > latestVersion.core[index] {
			return 1
		}
	}
	return comparePrerelease(currentVersion.prerelease, latestVersion.prerelease)
}

func parseSemanticVersion(value string) (semanticVersion, bool) {
	value = strings.TrimPrefix(strings.TrimSpace(value), "v")
	if buildIndex := strings.IndexByte(value, '+'); buildIndex >= 0 {
		value = value[:buildIndex]
	}
	coreText := value
	prereleaseText := ""
	hasPrerelease := false
	if prereleaseIndex := strings.IndexByte(value, '-'); prereleaseIndex >= 0 {
		hasPrerelease = true
		coreText = value[:prereleaseIndex]
		prereleaseText = value[prereleaseIndex+1:]
	}
	coreParts := strings.Split(coreText, ".")
	if len(coreParts) != 3 {
		return semanticVersion{}, false
	}
	var result semanticVersion
	for index, part := range coreParts {
		if !validSemverNumericIdentifier(part) {
			return semanticVersion{}, false
		}
		number, err := strconv.Atoi(part)
		if err != nil {
			return semanticVersion{}, false
		}
		result.core[index] = number
	}
	if !hasPrerelease {
		return result, true
	}
	if prereleaseText == "" {
		return semanticVersion{}, false
	}
	result.prerelease = strings.Split(prereleaseText, ".")
	for _, identifier := range result.prerelease {
		if !validPrereleaseIdentifier(identifier) {
			return semanticVersion{}, false
		}
		if isNumericIdentifier(identifier) && len(identifier) > 1 && identifier[0] == '0' {
			return semanticVersion{}, false
		}
	}
	return result, true
}

func validSemverNumericIdentifier(value string) bool {
	return isNumericIdentifier(value) && (len(value) == 1 || value[0] != '0')
}

func isNumericIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func comparePrerelease(left, right []string) int {
	if len(left) == 0 && len(right) == 0 {
		return 0
	}
	if len(left) == 0 {
		return 1
	}
	if len(right) == 0 {
		return -1
	}
	count := len(left)
	if len(right) < count {
		count = len(right)
	}
	for index := 0; index < count; index++ {
		leftNumeric := isNumericIdentifier(left[index])
		rightNumeric := isNumericIdentifier(right[index])
		switch {
		case leftNumeric && rightNumeric:
			if len(left[index]) < len(right[index]) {
				return -1
			}
			if len(left[index]) > len(right[index]) {
				return 1
			}
			if left[index] < right[index] {
				return -1
			}
			if left[index] > right[index] {
				return 1
			}
		case leftNumeric:
			return -1
		case rightNumeric:
			return 1
		default:
			if left[index] < right[index] {
				return -1
			}
			if left[index] > right[index] {
				return 1
			}
		}
	}
	if len(left) < len(right) {
		return -1
	}
	if len(left) > len(right) {
		return 1
	}
	return 0
}

func compareLooseVersionCore(left, right string) int {
	parse := func(value string) [3]int {
		value = strings.TrimPrefix(strings.TrimSpace(value), "v")
		parts := strings.Split(value, ".")
		result := [3]int{}
		for index := 0; index < len(parts) && index < len(result); index++ {
			numberText := strings.SplitN(parts[index], "-", 2)[0]
			if number, err := strconv.Atoi(numberText); err == nil {
				result[index] = number
			}
		}
		return result
	}
	leftCore := parse(left)
	rightCore := parse(right)
	for index := range leftCore {
		if leftCore[index] < rightCore[index] {
			return -1
		}
		if leftCore[index] > rightCore[index] {
			return 1
		}
	}
	return 0
}

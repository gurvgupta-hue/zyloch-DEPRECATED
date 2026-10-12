"use client";
import React, { useEffect, useState } from "react";
import {
  ChevronDown,
  Building2,
  Folder,
  GitBranch,
  Loader2,
  X,
  Menu,
  User,
  Crown,
  Search,
  MoreVertical,
  RefreshCw,
} from "lucide-react";
import { useNavbar } from "@/hooks/useNavbar";
import SmartTruncate from "@/components/ui/SmartTruncate";
import { useDebounce } from "@/hooks/useDebounce";
import { ThemeToggle } from "@/components/ThemeToggle";

const RepoNavbar = ({ onToggleSidebar, hideSelectors = false }) => {
  const {
    installations,
    repositories,
    branches,
    selectedInstallation,
    selectedRepo,
    selectedBranch,
    loading,
    error,
    activeDropdown,
    dropdownRefs,
    setActiveDropdown,
    resetSelection,
    fetchInstallations,
    handleInstallationSelect,
    handleRepoSelect,
    handleBranchSelect,
    getAccountIcon,
  } = useNavbar();

  const [showMobileMenu, setShowMobileMenu] = useState(false);
  const [repoSearch, setRepoSearch] = useState("");
  const [branchSearch, setBranchSearch] = useState("");

  const debouncedSetRepoSearch = useDebounce((value) => {
    setRepoSearch(value);
  }, 500);

  const debouncedSetBranchSearch = useDebounce((value) => {
    setBranchSearch(value);
  }, 500);

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (showMobileMenu && !event.target.closest(".mobile-menu-container")) {
        setShowMobileMenu(false);
      }
    };
    document.addEventListener("click", handleClickOutside);
    return () => document.removeEventListener("click", handleClickOutside);
  }, [showMobileMenu]);

  useEffect(() => {
    fetchInstallations();
  }, [fetchInstallations]);

  const filteredRepositories = repositories.filter((repo) =>
    repo.full_name.toLowerCase().includes(repoSearch.toLowerCase())
  );

  const filteredBranches = branches.filter((branch) =>
    branch.name.toLowerCase().includes(branchSearch.toLowerCase())
  );

  const renderIcon = (type, size = 14) => {
    switch (type) {
      case "organization":
        return <Building2 size={size} className="text-[var(--color-primary)]" />;
      case "enterprise":
        return <Crown size={size} className="text-[var(--color-secondary)]" />;
      case "user":
        return <User size={size} className="text-[var(--success)]" />;
      case "repo":
        return <Folder size={size} className="text-[var(--color-primary)]" />;
      case "branch":
        return <GitBranch size={size} className="text-[var(--color-secondary)]" />;
      default:
        return <User size={size} className="text-[var(--muted)]" />;
    }
  };

  const SelectionPill = ({
    label,
    value,
    icon,
    onClear,
    showTooltip = false,
    compact = false,
  }) => {
    return (
      <div
        className={`group flex items-center gap-2 px-3 rounded-lg border border-cyan-500/20 bg-cyan-500/10 hover:bg-[var(--surface)] transition-colors duration-150 ease-out h-[38px] ${compact ? "w-full" : "min-w-[140px]"
          }`}
      >
        <div className="flex items-center gap-1.5 min-w-0 flex-1">
          {icon}
          <span className="text-sm font-semibold text-cyan-500 whitespace-nowrap">{label}:</span>
          <span className="text-xs text-[var(--text)] truncate max-w-[120px] font-medium">
            {showTooltip ? (
              <SmartTruncate
                text={value}
                type="auto"
                className="font-medium min-w-0"
                iconSize={12}
                threshold={compact ? 10 : 15}
                showIcon={false}
              />
            ) : (
              <span className="block truncate">{value}</span>
            )}
          </span>
        </div>

        <button
          onClick={(e) => {
            e.stopPropagation();
            onClear();
          }}
          className="p-0.5 text-[var(--muted)] hover:text-[var(--color-primary)] rounded group-hover:opacity-100 transition-all duration-150 ease-out flex-shrink-0"
          title={`Change ${label}`}
          aria-label={`Change ${label}`}
        >
          <X size={12} aria-hidden="true" />
        </button>
      </div>
    );
  };

  const DropdownButton = ({ type, label, loader, icon, disabled, compact = false }) => (
    <button
      className={`flex items-center gap-2 px-3 text-sm text-[var(--text)] bg-[var(--elevated-surface)] hover:bg-[var(--surface)] active:bg-[var(--border)] rounded-lg border border-[var(--border)] transition-all duration-150 active:scale-[0.98] group h-[38px] ${compact ? "w-full justify-start" : "min-w-[140px]"
        } ${disabled ? "opacity-50 cursor-not-allowed" : ""}`}
      onClick={() => {
        if (!disabled) {
          if (type === "repo") setRepoSearch("");
          if (type === "branch") setBranchSearch("");
          setActiveDropdown(activeDropdown === type ? null : type);
        }
      }}
      aria-expanded={activeDropdown === type}
      aria-haspopup="true"
    >
      {loader ? <Loader2 size={14} className="animate-spin text-[var(--muted)]" /> : icon}
      <span className="font-medium block truncate">{label}</span>
      {!compact && (
        <ChevronDown
          size={12}
          className={`text-[var(--muted)] ml-auto transition-transform duration-200 ${activeDropdown === type ? "rotate-180" : ""
            }`}
        />
      )}
    </button>
  );

  const DropdownOption = ({ option, type, onSelect }) => {
    const label =
      type === "installation"
        ? option.account.login
        : type === "repo"
          ? option.full_name.split("/")[1]
          : option.name;

    const iconType =
      type === "installation"
        ? getAccountIcon(option.account.type)
        : type === "repo"
          ? "repo"
          : "branch";

    return (
      <button
        className="flex items-center w-full px-3 py-2.5 text-sm hover:bg-[var(--elevated-surface)] active:bg-[var(--border)] transition-colors duration-100 ease-out group/item"
        onClick={() => {
          onSelect(option);
          setActiveDropdown(null);
        }}
      >
        {renderIcon(iconType, 14)}
        <span className="ml-2.5 text-[var(--text)] truncate flex-1 text-left group-hover/item:text-[var(--color-primary)] transition-colors">
          <SmartTruncate
            text={label}
            type="auto"
            className="text-sm min-w-0"
            iconSize={12}
            threshold={20}
            showIcon={false}
          />
        </span>
      </button>
    );
  };

  const SearchInput = ({ search, onChange, placeholder, total = null }) => (
    <div className="sticky top-0 px-3 py-2 bg-[var(--surface)] border-b border-[var(--border)]">
      <div className="relative">
        <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--muted)]" />

        <input
          type="text"
          defaultValue={search}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder}
          className="w-full pl-9 pr-3 py-1.5 text-sm bg-[var(--elevated-surface)] border border-[var(--border)] rounded-md focus:outline-none focus:ring-1 focus:ring-[var(--color-primary)] focus:border-[var(--color-primary)] text-[var(--text)] placeholder:text-[var(--muted)]"
          onClick={(e) => e.stopPropagation()}
          autoFocus
        />

        {total !== null && total > 0 && (
          <div className="absolute right-3 top-1/2 -translate-y-1/2">
            <span className="px-2 py-0.5 text-xs font-medium bg-[var(--color-primary)]/10 text-[var(--color-primary)] rounded-full">
              {total} total
            </span>
          </div>
        )}
      </div>
    </div>
  );

  const renderDropdown = (type) => {
    if (activeDropdown !== type) return null;

    const options =
      type === "installation"
        ? installations
        : type === "repo"
          ? filteredRepositories
          : filteredBranches;

    const loadingState =
      type === "installation"
        ? loading.installations
        : type === "repo"
          ? loading.repos
          : loading.branches;

    const handleSelect =
      type === "installation"
        ? handleInstallationSelect
        : type === "repo"
          ? handleRepoSelect
          : handleBranchSelect;

    const showSearch = type === "repo" || type === "branch";
    const originalTotalCount =
      type === "repo" ? repositories.length : type === "branch" ? branches.length : installations.length;

    return (
      <div
        ref={dropdownRefs[type]}
        className="absolute left-0 top-full mt-1 w-full sm:w-72 bg-[var(--surface)] rounded-lg shadow-xl border border-[var(--border)] z-50 max-h-80 overflow-y-auto will-change-transform backdrop-blur-sm bg-opacity-95 animate-fadeIn"
        style={{ animation: "fadeIn 0.2s ease-out", transformOrigin: "top left" }}
      >
        <div className="py-1">
          {type === "installation" && (
            <div className="flex items-center justify-between px-3 py-2 border-b border-[var(--border)]">
              <span className="text-xs font-semibold text-[var(--muted)] tracking-wide">
                Select Installation
              </span>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  fetchInstallations();
                }}
                className="p-1 hover:bg-[var(--elevated-surface)] rounded transition-all duration-150 active:scale-95"
                title="Refresh"
                aria-label="Refresh installations"
              >
                <RefreshCw size={12} className="text-[var(--muted)]" />
              </button>
            </div>
          )}

          {showSearch && (
            <SearchInput
              search={type === "repo" ? repoSearch : branchSearch}
              onChange={type === "repo" ? debouncedSetRepoSearch : debouncedSetBranchSearch}
              placeholder={type === "repo" ? "Search repositories..." : "Search branches..."}
              total={type === "repo" || type === "branch" ? originalTotalCount : null}
            />
          )}

          {loadingState ? (
            <div className="p-3 flex items-center justify-center gap-2 text-muted">
              <Loader2 size={14} className="animate-spin" /> Loading...
            </div>
          ) : options.length > 0 ? (
            <div className="max-h-64 overflow-y-auto">
              {options.map((option) => {
                const key =
                  type === "installation"
                    ? option.installationId ?? option.account?.id ?? option.account?.login
                    : type === "repo"
                      ? option.id ?? option.full_name
                      : option.name;

                return (
                  <DropdownOption
                    key={String(key)}
                    option={option}
                    type={type}
                    onSelect={handleSelect}
                  />
                );
              })}
            </div>
          ) : (
            <div className="p-4 text-center text-sm text-[var(--muted)]">No results found</div>
          )}
        </div>
      </div>
    );
  };

  const MobileMenuContent = () => (
    <div className="absolute left-4 right-4 top-full mt-1 bg-[var(--surface)] rounded-lg shadow-lg border border-[var(--border)] z-50 p-4 mobile-menu-container">
      <div className="space-y-4">
        <div className="space-y-2">
          <h3 className="text-xs font-semibold text-muted px-1">GitHub Account</h3>
          {selectedInstallation ? (
            <SelectionPill
              label="GitHub Account"
              value={selectedInstallation.account.login}
              icon={renderIcon(getAccountIcon(selectedInstallation.account.type), 14)}
              onClear={() => resetSelection("installation")}
              showTooltip={true}
              compact={true}
            />
          ) : (
            <div className="relative">
              <DropdownButton
                type="installation"
                label={loading.installations ? "Loading..." : "GitHub Account"}
                loader={loading.installations}
                icon={renderIcon("organization")}
                compact={true}
              />
              {renderDropdown("installation")}
            </div>
          )}
        </div>

        {selectedInstallation && (
          <div className="space-y-2">
            <h3 className="text-xs font-semibold text-muted px-1">Repository</h3>
            {selectedRepo ? (
              <SelectionPill
                label="Repository"
                value={selectedRepo.full_name.split("/")[1]}
                icon={renderIcon("repo")}
                onClear={() => resetSelection("repo")}
                showTooltip={true}
                compact={true}
              />
            ) : (
              <div className="relative">
                <DropdownButton
                  type="repo"
                  label={loading.repos ? "Loading..." : "Repository"}
                  loader={loading.repos}
                  icon={renderIcon("repo")}
                  disabled={!selectedInstallation || loading.repos}
                  compact={true}
                />
                {renderDropdown("repo")}
              </div>
            )}
          </div>
        )}

        {selectedRepo && !selectedRepo.archived && (
          <div className="space-y-2">
            <h3 className="text-xs font-semibold text-muted px-1">Branch</h3>
            {selectedBranch ? (
              <SelectionPill
                label="Branch"
                value={selectedBranch.name}
                icon={renderIcon("branch")}
                onClear={() => resetSelection("branch")}
                showTooltip={true}
                compact={true}
              />
            ) : (
              <div className="relative">
                <DropdownButton
                  type="branch"
                  label={loading.branches ? "Loading..." : "Branch"}
                  loader={loading.branches}
                  icon={renderIcon("branch")}
                  disabled={!selectedRepo || loading.branches}
                  compact={true}
                />
                {renderDropdown("branch")}
              </div>
            )}
          </div>
        )}

        {error && (
          <div className="mt-2 p-2 text-xs text-[var(--danger)] bg-[var(--danger)]/10 rounded border border-[var(--danger)]/30">
            <SmartTruncate
              text={error}
              type="auto"
              className="text-xs"
              iconSize={10}
              threshold={40}
              showIcon={false}
            />
          </div>
        )}

        <div className="pt-3 border-t border-default">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-muted">Theme</span>
            <ThemeToggle size="sm" />
          </div>
        </div>
      </div>
    </div>
  );

  return (
    <nav className="flex items-center justify-between gap-3 px-3 py-3 relative">
      <div className="flex items-center gap-3">
        <button
          onClick={onToggleSidebar}
          className="sm:hidden p-2 rounded-lg hover:bg-[var(--elevated-surface)] active:bg-[var(--border)] transition-all duration-150 active:scale-95 text-[var(--text)]"
          aria-label="Toggle sidebar"
        >
          <Menu size={20} aria-hidden="true" />
        </button>

        {!hideSelectors && (
          <div className="hidden sm:flex items-center gap-2 sm:gap-3 flex-1 min-w-0">
            {selectedInstallation ? (
              <SelectionPill
                label="GitHub Account"
                value={selectedInstallation.account.login}
                icon={renderIcon(getAccountIcon(selectedInstallation.account.type), 14)}
                onClear={() => resetSelection("installation")}
                showTooltip={true}
              />
            ) : (
              <div className="relative">
                <DropdownButton
                  type="installation"
                  label={loading.installations ? "Loading..." : "GitHub Account"}
                  loader={loading.installations}
                  icon={renderIcon("organization")}
                />
                {renderDropdown("installation")}
              </div>
            )}

            {selectedInstallation && (
              <>
                {selectedRepo ? (
                  <SelectionPill
                    label="Repository"
                    value={selectedRepo.full_name.split("/")[1]}
                    icon={renderIcon("repo")}
                    onClear={() => resetSelection("repo")}
                    showTooltip={true}
                  />
                ) : (
                  <div className="relative">
                    <DropdownButton
                      type="repo"
                      label={loading.repos ? "Loading..." : "Repository"}
                      loader={loading.repos}
                      icon={renderIcon("repo")}
                      disabled={!selectedInstallation || loading.repos}
                    />
                    {renderDropdown("repo")}
                  </div>
                )}
              </>
            )}

            {selectedRepo && !selectedRepo.archived && (
              <>
                {selectedBranch ? (
                  <SelectionPill
                    label="Branch"
                    value={selectedBranch.name}
                    icon={renderIcon("branch")}
                    onClear={() => resetSelection("branch")}
                    showTooltip={true}
                  />
                ) : (
                  <div className="relative">
                    <DropdownButton
                      type="branch"
                      label={loading.branches ? "Loading..." : "Branch"}
                      loader={loading.branches}
                      icon={renderIcon("branch")}
                      disabled={!selectedRepo || loading.branches}
                    />
                    {renderDropdown("branch")}
                  </div>
                )}
              </>
            )}
          </div>
        )}

        {!hideSelectors && (
          <div className="sm:hidden flex items-center gap-2 flex-1 min-w-0">
            {selectedInstallation ? (
              <SelectionPill
                label="GitHub Account"
                value={selectedInstallation.account.login}
                icon={renderIcon(getAccountIcon(selectedInstallation.account.type), 14)}
                onClear={() => resetSelection("installation")}
                compact={true}
              />
            ) : (
              <DropdownButton
                type="installation"
                label="GitHub Account"
                loader={loading.installations}
                icon={renderIcon("organization")}
                compact={true}
              />
            )}
          </div>
        )}
      </div>

      <div className="flex items-center gap-3 ml-auto">
        {error && (
          <div className="hidden sm:block px-3 py-1 text-xs text-[var(--danger)] bg-[var(--danger)]/10 rounded border border-[var(--danger)]/30 max-w-[200px]">
            <SmartTruncate
              text={error}
              type="auto"
              className="text-xs"
              iconSize={10}
              threshold={30}
              showIcon={false}
            />
          </div>
        )}

        <div className="flex items-center">
          <ThemeToggle size="sm" />
        </div>

        {!hideSelectors && (
          <>
            <button
              onClick={() => setShowMobileMenu(!showMobileMenu)}
              className="sm:hidden p-2 rounded-lg hover:bg-[var(--elevated-surface)] transition-all duration-150 text-[var(--text)] relative"
            >
              <MoreVertical size={20} />
              {(selectedRepo || selectedBranch) && (
                <span className="absolute -top-1 -right-1 w-2 h-2 bg-primary rounded-full"></span>
              )}
            </button>

            {showMobileMenu && <MobileMenuContent />}
          </>
        )}
      </div>
    </nav>
  );
};

export default RepoNavbar;
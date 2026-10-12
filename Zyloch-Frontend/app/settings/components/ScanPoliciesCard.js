// ScanPoliciesCard.jsx
"use client";

import React, { useCallback, useState } from 'react';
import { Lock } from 'lucide-react';
import { toast } from 'react-toastify';
import { useScanPolicies } from './ScanPolicies/useScanPolicies';
import { useSecretPolicies } from './ScanPolicies/useSecretPolicies';
import { ScanPoliciesSidebar } from './ScanPolicies/ScanPoliciesSidebar';
import ScanPoliciesList from './ScanPolicies/ScanPoliciesList';
import { MobileMenu } from './ScanPolicies/MobileMenu';

const SECRET_SUBCATEGORIES = new Set([
  'dlp-pii', 'dlp-pci', 'dlp-phi',
  'api-keys', 'access-tokens', 'credentials', 'generic-secrets',
]);

const ScanPoliciesCard = ({
  orgName,
  activeView = 'policies',
  onTabChange = () => { },
  canEdit = false,
}) => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [sidebarCompact, setSidebarCompact] = useState(false);

  const {
    selectedCategory,
    setSelectedCategory,
    selectedSubCategory,
    setSelectedSubCategory,
    expandedCategories,
    toggleCategory,
    policies: scanPolicies,
    handlePolicyToggle: scanHandlePolicyToggle,
    handleSeverityChange: scanHandleSeverityChange,
    handleBulkToggle: scanHandleBulkToggle,
    getSeverityColor: scanGetSeverityColor,
    getSeverityIcon: scanGetSeverityIcon,
    scanCategories,
    navGroups,
    policyStats: scanPolicyStats,
    getCategoryCount: scanGetCategoryCount,
    unsavedChangesCount,
    savePreferences,
    discardChanges,
  } = useScanPolicies({ orgName });

  const {
    policies: secretPolicies,
    handlePolicyToggle: secretHandlePolicyToggle,
    handleBulkToggle: secretHandleBulkToggle,
    policyStats: secretPolicyStats,
    getCategoryCount: secretGetCategoryCount,
    getSeverityColor: secretGetSeverityColor,
    getSeverityIcon: secretGetSeverityIcon,
    unsavedChangesCount: secretUnsavedChangesCount,
    savePreferences: secretSavePreferences,
    discardChanges: secretDiscardChanges,
  } = useSecretPolicies({ orgName });

  const isSecretView = SECRET_SUBCATEGORIES.has(selectedSubCategory);
  const policies = isSecretView ? secretPolicies : scanPolicies;
  const getSeverityColor = isSecretView ? secretGetSeverityColor : scanGetSeverityColor;
  const activeUnsavedChangesCount = isSecretView ? secretUnsavedChangesCount : unsavedChangesCount;
  const activeSavePreferences = isSecretView ? secretSavePreferences : savePreferences;
  const activeDiscardChanges = isSecretView ? secretDiscardChanges : discardChanges;

  // Policy writes require `organization.settings.write` (admin). Members get a
  // read-only view instead of controls whose writes the backend would reject.
  const denyEdit = useCallback(() => {
    toast.info('Only organization admins can change scan policies');
  }, []);

  const handlePolicyToggle = canEdit
    ? (isSecretView ? secretHandlePolicyToggle : scanHandlePolicyToggle)
    : denyEdit;
  const handleBulkToggle = canEdit
    ? (isSecretView ? secretHandleBulkToggle : scanHandleBulkToggle)
    : denyEdit;
  const handleSeverityChange = canEdit ? scanHandleSeverityChange : denyEdit;

  const totalPolicies = scanPolicyStats.totalPolicies + secretPolicyStats.totalPolicies;
  const enabledPolicies = scanPolicyStats.enabledPolicies + secretPolicyStats.enabledPolicies;
  const disabledPolicies = scanPolicyStats.disabledPolicies + secretPolicyStats.disabledPolicies;
  const policyStats = {
    totalPolicies,
    enabledPolicies,
    disabledPolicies,
    enabledPercentage: totalPolicies > 0 ? Math.round((enabledPolicies / totalPolicies) * 100) : 0,
    disabledPercentage: totalPolicies > 0 ? Math.round((disabledPolicies / totalPolicies) * 100) : 0,
  };
  const getSeverityIcon = isSecretView ? secretGetSeverityIcon : scanGetSeverityIcon;
  const getCategoryCount = (category) =>
    category.id === 'secrets' ? secretGetCategoryCount(category) : scanGetCategoryCount(category);

  const selectedCategoryData = scanCategories.find(cat => cat.id === selectedCategory);
  const selectedPolicies = policies[selectedSubCategory] || [];

  return (
    <>
      <MobileMenu
        isOpen={mobileMenuOpen}
        onClose={() => setMobileMenuOpen(false)}
        scanCategories={scanCategories}
        onSelectCategory={(categoryId) => {
          setSelectedCategory(categoryId);
          const category = scanCategories.find(cat => cat.id === categoryId);
          if (category?.subCategories.length === 1) {
            setSelectedSubCategory(category.subCategories[0].id);
          }
          setMobileMenuOpen(false);
        }}
      />

      {!canEdit && (
        <div
          className="flex items-center gap-2 px-4 py-2 text-sm"
          style={{
            background: 'color-mix(in srgb, var(--muted) 12%, transparent)',
            borderBottom: '1px solid var(--border)',
            color: 'var(--muted)',
          }}
        >
          <Lock size={14} />
          <span>Read-only — only organization admins can change scan policies.</span>
        </div>
      )}

      <div className="flex flex-row flex-1 w-full h-full relative">
        <ScanPoliciesSidebar
          sidebarCompact={sidebarCompact}
          setSidebarCompact={setSidebarCompact}
          selectedCategory={selectedCategory}
          setSelectedCategory={setSelectedCategory}
          selectedSubCategory={selectedSubCategory}
          setSelectedSubCategory={setSelectedSubCategory}
          expandedCategories={expandedCategories}
          toggleCategory={toggleCategory}
          scanCategories={scanCategories}
          navGroups={navGroups}
          policies={policies}
          canEdit={canEdit}
          policyStats={policyStats}
          getCategoryCount={getCategoryCount}
        />

        <ScanPoliciesList
          selectedCategory={selectedCategory}
          selectedSubCategory={selectedSubCategory}
          selectedCategoryData={selectedCategoryData}
          selectedPolicies={selectedPolicies}
          scanCategories={scanCategories}
          policies={policies}
          onPolicyToggle={handlePolicyToggle}
          onSeverityChange={handleSeverityChange}
          getSeverityColor={getSeverityColor}
          getSeverityIcon={getSeverityIcon}
          activeTab={activeView}
          onTabChange={onTabChange}
          onBulkToggle={handleBulkToggle}
          canEdit={canEdit}
          onMobileMenuOpen={() => setMobileMenuOpen(true)}
          onCategoryChange={(categoryId, subCategoryId) => {
            setSelectedCategory(categoryId);
            setSelectedSubCategory(subCategoryId);
          }}
          unsavedChangesCount={activeUnsavedChangesCount}
          onSavePreferences={activeSavePreferences}
          onDiscardChanges={activeDiscardChanges}
        />
      </div>
    </>
  );
};

export default ScanPoliciesCard;
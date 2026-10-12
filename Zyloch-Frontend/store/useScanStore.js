"use client";
import { create } from "zustand";
import { toast } from "react-toastify";

import {
  startScan,
  getScans,
  getLatestScan,
  getScan,
  clearCache,
} from "@/lib/api/scans";

const POLL_INTERVAL_MS = 10000; // 10 seconds
const MAX_POLLING_DURATION_MS = 30 * 60 * 1000; // 30 minutes
const MAX_POLL_ATTEMPTS = Math.floor(MAX_POLLING_DURATION_MS / POLL_INTERVAL_MS);

export const useScanStore = create((set, get) => ({
  /* ============================================================
     STATE
  ============================================================ */
  scans: [],
  latestScan: null,
  currentScan: null,

  loading: false,               // used for "fetch latest scan"
  startingScan: false,          // used when starting a new scan
  refreshingScan: false,        // used when refreshing a scan
  pollingScan: false,           // track if we're polling for scan completion
  pollingInterval: null,        // store the polling interval ID

  error: null,
  successMessage: null,

  /* ============================================================
     UTILITIES
  ============================================================ */

  clearStatus: () => {
    // Clear any existing polling interval
    const { pollingInterval } = get();
    if (pollingInterval) {
      clearInterval(pollingInterval);
    }
    
    set({ 
      loading: false, 
      startingScan: false, 
      refreshingScan: false, 
      pollingScan: false, 
      pollingInterval: null,
      error: null 
    });
  },

  clearLatestScan: () => set({ latestScan: null }),

  clearScanCache: (pattern = "") => {
    try {
      clearCache(pattern);
      toast.info("Cache cleared successfully");
    } catch (err) {
      toast.error(`Cache clear failed: ${err.message}`);
    }
  },

  /* ============================================================
     HELPER: POLL FOR SCAN BY ID
  ============================================================ */
  pollForScanById: async (
    scanId,
    installationId,
    org = null,
    repo = null,
    branch = "main",
    scanType = "all",
    maxAttempts = MAX_POLL_ATTEMPTS,
    interval = POLL_INTERVAL_MS
  ) => {
    // Clear any existing interval
    const { pollingInterval } = get();
    if (pollingInterval) {
      clearInterval(pollingInterval);
    }

    let attempts = 0;
    let pollInterval = null;

    const poll = async () => {
      attempts++;
      
      try {
        const data = await getScan(scanId, installationId, { bypassCache: true });
        
        if (data && data.scan_id && data.scan_status) {
          const status = data.scan_status.toLowerCase();
          
          // Check for completed status
          if (status === "completed") {
            // Clear the interval
            if (pollInterval) {
              clearInterval(pollInterval);
            }
            
            clearCache();

            let finalScanData = data;
            if (org && repo) {
              try {
                const freshData = await getLatestScan(
                  installationId,
                  org,
                  repo,
                  branch,
                  scanType,
                  { bypassCache: true }
                );
                if (freshData) {
                  finalScanData = freshData;
                }
              } catch (fetchErr) {
                console.warn("fetchLatestScan after completion error:", fetchErr);
              }
            }

            set({ 
              latestScan: finalScanData,
              currentScan: finalScanData,
              pollingScan: false,
              startingScan: false,
              loading: false,
              pollingInterval: null,
              successMessage: "Scan completed successfully"
            });
            
            toast.success(`Scan completed: ${data.scan_id}`);
            return true;
          }
          
          // Check for failed status
          if (status === "failed" || status === "error" || status === "failure") {
            if (pollInterval) {
              clearInterval(pollInterval);
            }
            
            set({ 
              pollingScan: false,
              startingScan: false,
              pollingInterval: null,
              error: `Scan failed: ${data.error_message || data.message || data.detail || "Unknown error"}`
            });
            
            toast.error(`Scan ${scanId} failed`);
            return false;
          }
          
          // Check for in-progress statuses
          const inProgressStatuses = ["pending", "queued", "running", "processing", "in_progress"];
          if (inProgressStatuses.includes(status)) {
          }
        }
        
        // If max attempts reached, stop polling
        if (attempts >= maxAttempts) {
          if (pollInterval) {
            clearInterval(pollInterval);
          }
          
          set({ 
            pollingScan: false,
            startingScan: false,
            pollingInterval: null,
            error: "Scan timeout: Scan took too long to complete (30 minutes)"
          });
          
          toast.warning(`Scan ${scanId} is taking longer than expected`);
          return false;
        }
        
      } catch (err) {
        
        // If scan not found yet, continue polling
        const notFoundErrors = ["404", "not found", "Scan not found", "does not exist"];
        const isNotFound = notFoundErrors.some(error => 
          err.message.toLowerCase().includes(error.toLowerCase())
        );
        
        if (isNotFound) {
          if (attempts >= maxAttempts) {
            if (pollInterval) {
              clearInterval(pollInterval);
            }
            
            set({ 
              pollingScan: false,
              startingScan: false,
              pollingInterval: null,
              error: "Scan not found after multiple attempts"
            });
            
            toast.error(`Scan ${scanId} not found`);
            return false;
          }
          return; // Continue polling
        }
        
        // Other errors - stop polling
        if (pollInterval) {
          clearInterval(pollInterval);
        }
        
        set({ 
          pollingScan: false,
          startingScan: false,
          pollingInterval: null,
          error: err.message
        });
        
        toast.error(`Error checking scan status: ${err.message}`);
        return false;
      }
    };
    
    // Start polling immediately
    poll();
    
    // Set up interval for continuous polling
    pollInterval = setInterval(poll, interval);
    
    // Store interval ID in state
    set({ pollingInterval: pollInterval });
    
    // Return the interval ID for external control
    return pollInterval;
  },

  /* ============================================================
     FETCH MULTIPLE SCANS
  ============================================================ */
  fetchScans: async (installationId, org, repo, limit = 50) => {
    set({ loading: true, error: null });

    try {
      const data = await getScans(installationId, org, repo, limit);
      set({ scans: data || [], loading: false });

      return data;
    } catch (err) {
      set({ error: err.message, loading: false });
      toast.error(`Error fetching scans: ${err.message}`);
    }
  },

  /* ============================================================
     FETCH LATEST SCAN
  ============================================================ */
  fetchLatestScan: async (
    installationId,
    org,
    repo,
    branch = "main",
    scanType = null,
    bypassCache = false
  ) => {
    set({ loading: true, error: null });

    try {
      const data = await getLatestScan(
        installationId,
        org,
        repo,
        branch,
        scanType,
        { bypassCache }
      );

      set({
        latestScan: data || null,
        loading: false,
      });

      return data;
    } catch (err) {
      const errorMsg = String(err.message || "").toLowerCase();
      const isNotFound =
        err.status === 404 ||
        (errorMsg.includes("no") && (errorMsg.includes("scan found") || errorMsg.includes("scans found") || errorMsg.includes("scans available"))) ||
        errorMsg.includes("scan not found") ||
        errorMsg.includes("not found");

      if (isNotFound) {
        // Uninitiated scanner is a normal state, not an error
        set({ latestScan: null, error: null, loading: false });
        return null;
      }

      toast.error(`Error fetching scan: ${err.message}`);
      set({ error: err.message, loading: false });
    }
  },

  /* ============================================================
     FETCH SCAN DETAILS BY ID
  ============================================================ */
  fetchScanById: async (scanId, installationId) => {
    set({ loading: true, error: null });

    try {
      const data = await getScan(scanId, installationId);

      set({
        currentScan: data || null,
        loading: false,
      });

      return data;
    } catch (err) {
      set({ error: err.message, loading: false });
      toast.error(`Error loading scan details: ${err.message}`);
    }
  },

  /* ============================================================
     START A NEW SCAN — WITH POLLING BY SCAN ID
  ============================================================ */
  initiateScan: async (
    installationId,
    org,
    repo,
    branch = "main",
    type = "all"
  ) => {
    // Clear any existing polling
    get().clearStatus();
    
    // 1️⃣ Immediately show UI blocking loader
    set({
      startingScan: true,
      pollingScan: true,
      error: null,
      successMessage: null,
      latestScan: null,   // Clear old data
    });

    try {
      // 2️⃣ Start the scan
      const response = await startScan(installationId, org, repo, branch, type);
      
      
      // Extract scan ID from response
      let scanId = null;
      
      if (response && response.scan_id) {
        scanId = response.scan_id;
      } else if (response && response.scanId) {
        scanId = response.scanId;
      } else if (response && response.id) {
        scanId = response.id;
      } else if (typeof response === "string") {
        // If response is a string, it might be the scan ID
        scanId = response;
      } else if (response && response._id) {
        // Use _id as fallback
        scanId = response._id;
      }
      
      if (scanId) {
        set({
          successMessage: "Scan initiated successfully",
        });

        toast.success(`Scan ${scanId} started. Polling for completion...`);
        
        // 3️⃣ Start polling by scan ID after a short delay
        setTimeout(() => {
          get().pollForScanById(scanId, installationId, org, repo, branch, type);
        }, 3000); // Wait 3 seconds before starting to poll
        
        return { scanId, ...response };
      } else {
        // No scan ID returned - fallback to polling latest scan
        console.warn("No scan ID returned from startScan API, falling back to polling latest scan");
        
        set({
          successMessage: "Scan initiated, waiting for completion...",
        });
        
        toast.success(`Scan started for ${repo}/${branch}. Waiting for completion...`);
        
        // Start polling latest scan
        const pollLatest = async () => {
          let attempts = 0;
          const maxAttempts = MAX_POLL_ATTEMPTS;
          
          const interval = setInterval(async () => {
            attempts++;
            
            try {
              const latestData = await getLatestScan(
                installationId,
                org,
                repo,
                branch,
                type,
                { bypassCache: true }
              );
              
              if (latestData && latestData.scan_status === "completed") {
                clearInterval(interval);
                clearCache();
                set({ 
                  latestScan: latestData,
                  currentScan: latestData,
                  pollingScan: false,
                  startingScan: false,
                  loading: false,
                  pollingInterval: null,
                  successMessage: "Scan completed successfully"
                });
                toast.success(`Scan completed for ${repo}/${branch}`);
              }
              
              if (attempts >= maxAttempts) {
                clearInterval(interval);
                set({ 
                  pollingScan: false,
                  startingScan: false,
                  pollingInterval: null,
                  error: "Scan timeout: Could not detect completed scan"
                });
                toast.warning(`Scan for ${repo}/${branch} is taking longer than expected`);
              }
            } catch (err) {
              // Continue polling on errors
              if (attempts >= maxAttempts) {
                clearInterval(interval);
                set({ 
                  pollingScan: false,
                  startingScan: false,
                  pollingInterval: null,
                  error: err.message
                });
              }
            }
          }, POLL_INTERVAL_MS); // Poll every 10 seconds
          
          // Store interval
          set({ pollingInterval: interval });
        };
        
        // Start polling after delay
        setTimeout(pollLatest, 5000);
        
        return response;
      }
      
    } catch (err) {
      set({
        error: err.message,
        startingScan: false,
        pollingScan: false,
      });

      toast.error(`Scan initiation failed: ${err.message}`);
    }
  },

  /* ============================================================
     REFRESH EXISTING SCAN
  ============================================================ */
  refreshScan: async (installationId, org, repo, branch = "main", scanType = null) => {
    // Clear any existing polling
    get().clearStatus();
    clearCache();
    
    set({
      refreshingScan: true,
      error: null,
    });

    // Clear previous scan to avoid stale UI
    set({ latestScan: null });

    try {
      await get().fetchLatestScan(installationId, org, repo, branch, scanType, true);
    } catch (err) {
      set({ error: err.message });
    }

    set({ refreshingScan: false });
  },

  /* ============================================================
     MANUALLY STOP POLLING
  ============================================================ */
  stopPolling: () => {
    const { pollingInterval } = get();
    if (pollingInterval) {
      clearInterval(pollingInterval);
    }
    
    set({ 
      pollingScan: false, 
      startingScan: false,
      pollingInterval: null 
    });
    
    toast.info("Scan polling stopped");
  },
}));

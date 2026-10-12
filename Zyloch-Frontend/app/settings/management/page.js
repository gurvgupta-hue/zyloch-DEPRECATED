"use client";

import React, { useState, useEffect } from "react";
import { Building2, Key, Settings } from "lucide-react";
import { OAuthConfigCard } from "../components/OAuthConfigCard";
import { OrganizationDetailsCard } from "../components/OrganizationDetailsCard";
import { SettingsPageHeader } from "../components/SettingsPageHeader";

const ManagementPage = () => {
  const [isAdmin, setIsAdmin] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchUserRole();
  }, []);

  const fetchUserRole = async () => {
    try {
        const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/organization`, {
        credentials: "include"
      });

      if (response.ok) {
        const data = await response.json();
        setIsAdmin(data.organization?.userRole === "admin");
      }
    } catch (error) {
      console.error("Error fetching user role:", error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <SettingsPageHeader
        icon={Settings}
        title="Organization Management"
        subtitle="Manage your OAuth configuration and organization details"
        badge={
          isAdmin
            ? {
                label: "Administrator Access",
                color: "var(--success)",
                background:
                  "color-mix(in srgb, var(--success) 12%, transparent)",
                border:
                  "1px solid color-mix(in srgb, var(--success) 30%, transparent)",
              }
            : null
        }
      />

      <div className="space-y-5 lg:space-y-0 lg:gap-6 lg:items-start">
        {/* Organization Details Card - Always visible */}
        <div className="lg:flex-1">
          <div 
            className="fade-in"
            style={{
              background: 'var(--surface)',
              borderRadius: 'var(--radius-xl)',
              boxShadow: 'var(--shadow-1)',
              transition: 'all var(--transition-normal) var(--ease-smooth)',
              '--hover-shadow': 'var(--shadow-2)'
            }}
            onMouseOver={(e) => {
              e.currentTarget.style.boxShadow = 'var(--hover-shadow)';
            }}
            onMouseOut={(e) => {
              e.currentTarget.style.boxShadow = 'var(--shadow-1)';
            }}
          >
            <div className="relative p-6 pb-0">
              <div 
                className="absolute top-0 left-0 w-full h-1 rounded-t-xl"
                style={{
                  background: 'linear-gradient(to right, color-mix(in srgb, var(--color-accent) 30%, transparent), var(--color-accent), color-mix(in srgb, var(--color-accent) 30%, transparent))'
                }}
              ></div>
              
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-3">
                  <div 
                    className="w-10 h-14 rounded-xl flex items-center justify-center flex-shrink-0"
                    style={{
                      background: 'linear-gradient(135deg, color-mix(in srgb, var(--color-accent) 10%, transparent), color-mix(in srgb, var(--color-primary) 10%, transparent))',
                      boxShadow: 'var(--shadow-2)'
                    }}
                  >
                    <Building2 size={20} style={{ color: 'var(--color-accent)' }} />
                  </div>
                  <div>
                    <h2 className="text-lg font-semibold" style={{ color: 'var(--text)' }}>Organization Details</h2>
                    <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>
                      View and manage your organization information
                    </p>
                  </div>
                </div>
                
                <div className="flex items-center gap-3">
                  {isAdmin ? (
                    <span 
                      className="text-xs px-3 py-1.5 rounded-full font-medium"
                      style={{
                        background: 'color-mix(in srgb, var(--color-primary) 10%, transparent)',
                        color: 'var(--color-primary)',
                        border: '1px solid color-mix(in srgb, var(--color-primary) 20%, transparent)'
                      }}
                    >
                      Admin
                    </span>
                  ) : (
                    <span 
                      className="text-xs px-3 py-1.5 rounded-full font-medium"
                      style={{
                        background: 'color-mix(in srgb, var(--muted) 10%, transparent)',
                        color: 'var(--muted)',
                        border: '1px solid color-mix(in srgb, var(--muted) 20%, transparent)'
                      }}
                    >
                      View Only
                    </span>
                  )}
                </div>
              </div>
            </div>
            
            <OrganizationDetailsCard isAdmin={isAdmin} />
          </div>
        </div>

        {/* OAuth Configuration Card - Only for admins */}
        {!loading && isAdmin && (
          <div className="lg:flex-1">
            <div 
              className="fade-in"
              style={{
                background: 'var(--surface)',
                borderRadius: 'var(--radius-xl)',
                boxShadow: 'var(--shadow-1)',
                transition: 'all var(--transition-normal) var(--ease-smooth)',
                '--hover-shadow': 'var(--shadow-2)'
              }}
              onMouseOver={(e) => {
                e.currentTarget.style.boxShadow = 'var(--hover-shadow)';
              }}
              onMouseOut={(e) => {
                e.currentTarget.style.boxShadow = 'var(--shadow-1)';
              }}
            >
              <div className="relative p-6 pb-0">
                <div 
                  className="absolute top-0 left-0 w-full h-1 rounded-t-xl"
                  style={{
                    background: 'linear-gradient(to right, color-mix(in srgb, var(--warning) 30%, transparent), var(--warning), color-mix(in srgb, var(--warning) 30%, transparent))'
                  }}
                ></div>
                
                <div className="flex items-center justify-between mb-6">
                  <div className="flex items-center gap-3">
                    <div 
                      className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0"
                      style={{
                        background: 'linear-gradient(135deg, color-mix(in srgb, var(--warning) 10%, transparent), color-mix(in srgb, var(--color-primary) 10%, transparent))',
                        boxShadow: 'var(--shadow-2)'
                      }}
                    >
                      <Key size={20} style={{ color: 'var(--warning)' }} />
                    </div>
                    <div>
                      <h2 className="text-lg font-semibold" style={{ color: 'var(--text)' }}>OAuth Configuration</h2>
                      <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>
                        Manage authentication providers
                      </p>
                    </div>
                  </div>
                  
                  <span 
                    className="text-xs px-3 py-1.5 rounded-full font-medium"
                    style={{
                      background: 'color-mix(in srgb, var(--warning) 10%, transparent)',
                      color: 'var(--warning)',
                      border: '1px solid color-mix(in srgb, var(--warning) 20%, transparent)'
                    }}
                  >
                    Admin Only
                  </span>
                </div>
              </div>
              
              <OAuthConfigCard />
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ManagementPage;
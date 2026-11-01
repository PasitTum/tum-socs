// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

export interface UserProfile {
  username: string;
  fullName: string;
  role: 'Administrator' | 'SOCAnalyst' | 'ComplianceAuditor' | string;
  department: string;
}

export interface LoginResponse {
  token: string;
  tokenType: string;
  expiresInSeconds: number;
  user: UserProfile;
}

export interface DatasetItemInfo {
  id: string;
  name: string;
  category: string;
  source: string;
  description: string;
  mitreTechniques: string[];
  recordCount: number;
}

export interface DatasetCatalogResponse {
  datasets: DatasetItemInfo[];
  totalAvailableRecords: number;
}

export interface DatasetOperationResult {
  success: boolean;
  message: string;
  ingestedCount: number;
  threatMatchesCount: number;
  piiRedactedCount: number;
  globalMerkleRoot: string;
  timestampUtc: string;
}

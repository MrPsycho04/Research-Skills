---
name: hunt-sqli
description: Hunting skill for sqli vulnerabilities. Built from 12 public bug bounty reports including modern NoSQL injection (Rocket.Chat CVE-2021-22911 MongoDB $regex, Mongoose ORM CVE-2024-53900 $where bypass), modern ORM raw-fragment SQLi (Django CVE-2024-42005, Sequelize GHSA-wrh9-cjv3-2hpw), second-order SQL injection (HackerOne Salesforce), time-based blind SQLi in GraphQL resolvers, and SQLi on OIDC-proxy backends. Use when hunting SQLi on any target. Dedicated NoSQL operator injection (MongoDB/CouchDB $where/$regex/$ne) is owned by hunt-nosqli — NoSQL appears here only as adjacent ORM/WAF context.
sources: github, hackerone_public, github_security_advisories, snyk_research, sonarsource_research
report_count: 29
---

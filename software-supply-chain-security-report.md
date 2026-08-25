# Securing the Software Supply Chain: Strategic Approaches to Scaling Development with AI Adoption

**Melinda Marks** | *Practice Director, Cybersecurity*  
**Omdia** (by Informa TechTarget) | April 2026  
*Commissioned by Docker*

---

## Research Objectives

Modern software development practices prioritize collaboration and speed of delivery, but this commensurately increases the complexity of the software supply chain. Security teams need to address elements that can exacerbate the attack surface, including source code, third-party and open source software (OSS) code and libraries, and developer tools and processes.

Further, software security is complicated by increasing AI usage, including generative AI assistive tools to build code and agentic AI that can autonomously perform tasks. These dynamics bring up important questions, such as: How do organizations enable developer speed and innovation without increasing vulnerabilities across the software supply chain? What strategies are teams developing to secure the software supply chain while supporting the demands of cloud-native application development?

To understand these trends and the resulting market dynamics, Omdia executed a survey of **400 IT, cybersecurity, and application professionals** at organizations in North America responsible for evaluating or purchasing technology products and services to secure their organization's software supply chain.

**This study sought to:**

- **Assess** usage of third-party software components, including OSS, and its impact on security.
- **Determine** the impact of attacks and incidents focused on the software supply chain.
- **Examine** current solutions in place, their effectiveness, and their integration with cloud and application security products.
- **Validate** key stakeholders and investment plans for software supply chain security.

> *Note: Totals in figures and tables throughout this report may not add up to 100% due to rounding or organizations choosing more than one answer to select questions.*

---

## Key Findings

1. [Organizations need to address security risk with increasing usage of third-party code and AI adoption](#1-third-party-code--ai-adoption)
2. [Security teams face challenges with current software supply chain solutions](#2-challenges-with-current-solutions)
3. [OSS is vital to developers and must be supported](#3-oss-is-vital)
4. [Effective inventory and software bill of materials tools can help meet security and compliance objectives](#4-sbom--inventory)
5. [The rapidly evolving threat landscape requires preventative measures and rapid response](#5-threat-landscape)
6. [Investment plans prioritizing AI require collaboration across teams](#6-investment-plans)

---

## 1. Third-Party Code & AI Adoption

### Software Applications Include Increasing Percentages of Third-Party Code

Utilizing prebuilt third-party software code helps developers who are under pressure to increase productivity and deliver sophisticated software applications. Teams are increasingly utilizing third-party code to save time in building their applications.

- **37%** of organizations report that more than half of their total software code comes from third-party sources today.
- This is expected to increase to **57%** of organizations over the next 12 months.

**Approximate % of total software code that is third-party (today vs. 12 months):**

| Range | Today | 12 Months |
|-------|-------|-----------|
| 10% or less | 3% | 2% |
| 11–20% | 12% | 7% |
| 21–30% | 16% | 9% |
| 31–40% | 18% | 12% |
| 41–50% | 15% | 14% |
| 51–60% | 12% | 13% |
| 61–70% | 16% | 12% |
| 71–80% | 6% | 20% |
| 81–90% | 2% | 7% |
| 91–100% | 1% | 5% |

---

### Organizations Report a Wide Variety of Security Concerns with Third-Party Software

The increasing percentages of third-party and open source code components impact security programs and cause many areas of concern. Only **6%** of organizations cited no challenges or concerns with third-party software.

**Challenges or concerns with using third-party software including OSS:**

| Challenge | % |
|-----------|---|
| Quickly remediating vulnerabilities | 39% |
| Identifying vulnerabilities in the code | 36% |
| AI increasing or generating vulnerable code | 35% |
| Understanding code composition and producing an SBOM | 33% |
| Trusting the source of the code | 33% |
| Ensuring code tracking to identify tampering | 32% |
| Detecting malicious packages before installation | 31% |
| Applying an issued patch quickly once released | 30% |
| Being victims of hackers targeting software dependencies | 30% |
| Having a high percentage of open source application code | 29% |
| Understanding software dependencies for running applications | 27% |
| Being victims of hackers targeting popular third-party/OSS code | 26% |
| Managing access for code changes | 24% |
| No challenges/concerns | 6% |

---

### AI Tops Elements of Concern for Software Supply Chain Risk

While increasing percentages of third-party code and OSS introduce complexity in software code composition, several elements contribute to increased security risk in the software supply chain. AI topped the list, followed closely by third-party and OSS code and software dependencies.

**Elements of the cloud-native technology stack posing the greatest risk:**

| Element | % |
|---------|---|
| AI technology (e.g., GenAI and securing data in LLMs) | 40% |
| Third-party and OSS code | 39% |
| Software dependencies | 38% |
| Cloud service provider (CSP) infrastructure | 31% |
| Infrastructure-as-code (IaC) | 23% |
| Data storage repositories | 19% |
| SCM repositories (e.g., GitHub and GitLab) | 17% |
| Application programming interfaces (APIs) | 17% |
| Container images | 15% |
| Virtual machines | 12% |
| Application code | 12% |
| Orchestration platforms (e.g., Kubernetes) | 12% |

---

## 2. Challenges with Current Solutions

### Nearly Half Do Not Feel They Have Robust Software Supply Chain Security

Organizations need a comprehensive program to secure their software supply chain, especially in light of increasing percentages of third-party code and usage of AI technologies in development.

**Assessment of current software supply chain security capabilities:**

| Capability Level | % |
|------------------|---|
| Robust program with the right processes and controls in place | 55% |
| Some processes and controls in place | 43% |
| Minimal policies, processes, and controls; rely too much on manual measures | 2% |

This is causing security teams to evaluate their current tool sets and look for ways to improve their programs to address the increasing complexity of mitigating risk across the software supply chain.

---

### Teams Need Effective Security Tools to Secure Third-Party and OSS Code

Secure container services or libraries of hardened container images were the only security tools for third-party and OSS code components that more than half of organizations identified as **very effective**.

**Effectiveness of security tools for third-party and OSS code components:**

| Tool | Very Effective | Moderately Effective | Minimally Effective | Not Using |
|------|---------------|----------------------|---------------------|-----------|
| Secure container service / hardened container images | 51% | 40% | 8% | 2% |
| Automated OSS package risk management | 48% | 43% | 8% | 2% |
| Solution providing vetted sources of OSS | 47% | 46% | 7% | 1% |
| Dependency analysis | 46% | 42% | 11% | 1% |
| Dynamic application security testing (DAST) | 46% | 45% | 9% | 1% |
| Static application security testing (SAST) | 45% | 46% | 9% | 1% |
| Configuration checks | 43% | 49% | 8% | 1% |
| License scanning | 42% | 43% | 14% | 1% |
| Applying SLSA framework | 39% | 42% | 15% | 4% |
| SBOM generation | 37% | 49% | 10% | 4% |
| Usage of Sigstore | 31% | 37% | 13% | 20% |

---

## 3. OSS Is Vital

### Organizations Have High Levels of Confidence in Secure OSS Usage

Total code composition increasingly includes open source software.

- **31%** of organizations report that more than half of their code is composed of OSS today.
- This is expected to jump to **51%** over the next 12 months.

**Confidence level that developers are *only* using secure OSS:**

| Level | % |
|-------|---|
| Completely confident | 31% |
| Confident | 50% |
| Somewhat confident | 13% |
| Not at all confident | 7% |

**Approximate % of total code that is OSS (today vs. 12 months):**

| Range | Today | 12 Months |
|-------|-------|-----------|
| 30% or less | 40% | 19% |
| 31–50% | 30% | 30% |
| 51–60% | 31% | 51% |

---

### Reliability of the Source Tops Assurance Factors for Secure OSS

Organizations look at a variety of factors to determine secure OSS. The biggest factor is the reliability of the vendor or source. Lower on the list are project disclosure policies, repository ratings, and whether the project has an active community.

**Factors or assurance processes used to determine OSS security:**

| Factor | % |
|--------|---|
| Reliability of the vendor or source | 47% |
| Governance process with automated analysis and policy enforcement | 43% |
| Assurance frameworks (e.g., SLSA and GUAC) | 43% |
| Secure container solutions | 42% |
| Solution offering pre-vetted secure OSS | 42% |
| Vendor tools or ratings | 40% |
| Governance process with manual analysis | 38% |
| Code signing for attribution and provenance (e.g., Sigstore) | 35% |
| Information in the registry or package manager | 33% |
| Frequency of releases or commits | 31% |
| The security scorecard | 30% |
| Whether the project has a responsible disclosure policy | 27% |
| Repository ratings | 27% |
| Whether the project has an active community | 24% |

---

## 4. SBOM & Inventory

### Incorporating SBOM Generation in Application Development Has Helped Mitigate Risk

**Do organizations currently generate an SBOM as part of their application development processes?**

| Status | % |
|--------|---|
| Yes — mandatory for all applications | 42% |
| Yes — on a case-by-case basis | 55% |
| No — but planning to over the next 12 months | 3% |

**How SBOMs have affected ability to manage software supply chain risk:**

| Impact | % |
|--------|---|
| Enables more efficient vulnerability mitigation | 73% |
| Enables implementation of security controls and processes | 72% |
| Helps meet compliance regulations | 68% |
| Provides a comprehensive view of all components and dependencies | 57% |
| Helps customers understand application composition | 53% |

---

### Teams Generate SBOMs from a Variety of Tools

Respondents often generate their SBOMs from multiple tools. More than a third are still generating them manually — showing an opportunity for security vendors to address these needs with easier-to-use SBOM tools.

**Tools or processes used to generate an SBOM:**

| Tool/Process | % |
|--------------|---|
| Software composition analysis (SCA) solution | 77% |
| Software supply chain security (SSCS) solution | 64% |
| Features from cloud service provider | 59% |
| Dedicated SBOM tool | 56% |
| Application security solution | 52% |
| Manual processes for inventory and tracking | 36% |

---

## 5. Threat Landscape

### Software Supply Chain Incidents

**77%** of organizations experienced a software supply chain incident in the last year. Many were preventable — the most common incident involved exploiting known vulnerabilities in third-party software, including OSS and container images.

**Software supply chain incidents experienced in the last 12 months:**

| Incident | % |
|----------|---|
| Exploit of known vulnerabilities in third-party software/OSS/container images | 38% |
| Secrets (keys, passwords, tokens) stolen from a source code repository | 28% |
| Exploit of a misconfigured cloud service | 27% |
| Zero-day exploit in third-party code/OSS/container images | 23% |
| Attack resulting in data loss due to insecure use of APIs | 22% |
| Compromised services account credentials | 22% |
| Compromised privileged user credentials | 20% |
| Zero-day software supply chain attack (dependency confusion, typosquatting, starjacking) | 20% |
| Attack on developer AI tools | 19% |
| No incidents in the last 12 months | 23% |

---

### Impacts of Software Supply Chain Security Incidents

**Impacts experienced from software supply chain security incidents:**

| Impact | % |
|--------|---|
| Unauthorized access to applications and data | 46% |
| Remediation steps impacted SLAs | 37% |
| Stolen developer credentials, secrets, or keys | 35% |
| Introduction of malware | 32% |
| Data loss | 31% |
| Introduction of ransomware | 25% |
| Introduction of crypto-jacking malware | 25% |
| Fines due to non-compliance with an industry regulation | 24% |
| No impacts experienced | 8% |

These outcomes underscore the importance of mitigating security risk early in the development lifecycle, ideally catching and remediating issues before applications are deployed.

---

## 6. Investment Plans

### Software Supply Chain Security Investments Are Set for a Variety of Plans

**Do organizations plan to invest in software supply chain security?**

| Plan | % |
|------|---|
| Expect to make significant investments | 62% |
| Expect to make moderate investments | 37% |

**Benefits organizations hope to achieve by investing in software supply chain security solutions:**

| Benefit | % |
|---------|---|
| Reduction in or avoidance of security incidents | 50% |
| Ability to fix code issues before deployment to production | 49% |
| Cost savings | 47% |
| Fewer security issues detected in runtime | 47% |
| Improved application uptime or availability | 46% |
| Time savings for the security team | 44% |
| More actionable data to inform remediations | 42% |
| Time savings for developers | 41% |

---

### Enabling Developers to Secure Their Code Is a High Priority

Enabling developers to secure their own code removes the security team from being a bottleneck. However, nearly half (45%) of security teams have only moderate or less influence over security products and processes for developers.

**Priority level for enabling developers to secure their code:**

| Priority | % |
|----------|---|
| Top application security priority | 32% |
| High priority (significant impact on security program) | 66% |
| Important but not a high priority | 2% |

**Can security teams influence security products and processes for developers?**

| Influence Level | % |
|-----------------|---|
| Significant influence | 55% |
| Moderate influence | 38% |
| Limited influence | 7% |
| No influence | 1% |

---

### Supporting Development Is a Critical Need

**Perceived comfort level of developers with taking on security responsibilities:**

| Level | % |
|-------|---|
| Completely comfortable | 45% |
| Mostly comfortable | 38% |
| Somewhat comfortable | 17% |
| Not at all comfortable | 1% |

**Why developers are uncomfortable with taking on security responsibilities:**

| Reason | % |
|--------|---|
| View security tasks as disruptive to development processes | 46% |
| Want to spend time developing product code | 46% |
| Organizational challenges — security and dev priorities not aligned | 32% |
| Security controls not embedded into default tools or base components | 30% |
| Lack security backgrounds | 30% |
| Believe the security team should do the security work | 29% |
| Don't like the security tools that have been recommended or purchased | 23% |
| Don't want to use separate security tools | 19% |
| Don't want to learn about security | 14% |

---

## Research Methodology and Demographics

Omdia conducted a comprehensive online survey of IT, cybersecurity, and application development professionals from private- and public-sector organizations in North America between **February 12, 2026, and February 25, 2026**. Respondents were required to be responsible for evaluating or purchasing technology products and services to secure their organization's software supply chain.

Final sample: **400 IT, cybersecurity, and application development professionals.**

**Respondents' organizations by number of employees:**

| Size | % |
|------|---|
| 100–499 | 12% |
| 500–999 | 14% |
| 1,000–2,499 | 28% |
| 2,500–4,999 | 24% |
| 5,000–9,999 | 12% |
| 10,000–19,999 | 6% |
| 20,000+ | 4% |

**Respondents' organizations by years in operation:**

| Years | % |
|-------|---|
| Less than 5 | 2% |
| 5–10 | 19% |
| 11–20 | 46% |
| 21–50 | 27% |
| More than 50 | 7% |

**Respondents' organizations by industry:**

| Industry | % |
|----------|---|
| Manufacturing | 19% |
| Financial | 19% |
| Retail/wholesale | 10% |
| Technology | 10% |
| Healthcare | 9% |
| Construction/engineering | 9% |
| Communications and media | 8% |
| Business services | 7% |
| Other | 11% |

---

## About Docker

Docker drives modern software development by making it easy to adopt container technology to radically boost productivity, security, testing, and collaboration at every step of the developer experience, including emerging AI workflows. Embraced by over 20 million developers worldwide, Docker's unmatched flexibility and choice make it the preferred tool for developers seeking efficiency and innovation for creating modern applications.

Learn more at [www.docker.com](https://www.docker.com)

---

*© 2026 TechTarget, Inc. All Rights Reserved. Unauthorized reproduction prohibited.*  
*This Omdia research and eBook was commissioned by Docker and is distributed under license from Informa TechTarget, Inc.*

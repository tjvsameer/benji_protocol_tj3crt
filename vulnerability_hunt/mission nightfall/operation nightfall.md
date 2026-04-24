# IMPOSSIBLE MISSIONS FORCE
## FIELD OPERATIVE BRIEFING — OPERATION NIGHTFALL
### Classification: EYES ONLY | COM5413 — The Benji Protocol | Week 5

---

```
THIS MESSAGE WILL NOT SELF-DESTRUCT.
IT WILL, HOWEVER, BE SUBMITTED TO MOODLE AND TAGGED ON GITHUB
BEFORE THE SESSION CLOCK STOPS.
```

---

> **Your mission, should you choose to accept it.**
>
> IMF intelligence has identified a live server operated by The Syndicate —
> a criminal organisation operating under the cover of a legitimate technology
> consultancy. The server contains operational records that confirm The
> Syndicate's current command structure, including the identity and access
> credentials of its Director, Solomon Lane.
>
> Ethan is already in the field. He needs the intelligence extracted, the
> access closed, and no trace of IMF involvement left on the system.
>
> Benji. That is your job.
>
> You have four hours. Your toolkit is already built.
> The target is live.

---

## SECTION 1 — PRE-MISSION SETUP
### Complete before the session clock starts

---

### 1.1 Import the Target VM

You received a password-protected archive in the session before this one.
The archive contains the target VM as an OVA file.

**The password to open the archive will be given to you at the start of this session.**

Do not ask for it early. It will not be provided early.

Once you have the password:

```bash
# The archive is named:
COM5413_OperationNightfall_Target.7z

# Extract with 7-zip:
7z x COM5413_OperationNightfall_Target.7z

# This produces:
COM5413_OperationNightfall.ova
```

Import the OVA into VirtualBox:

```
VirtualBox → File → Import Appliance → select COM5413_OperationNightfall.ova
```

Accept the default settings. Import takes approximately three to five minutes.
Do not modify any VM settings. Do not change the network adapter.

The VM is pre-configured on the `benji-lab` internal network at `172.16.19.200`.

> **If the import fails or the VM does not start:** raise your hand immediately.
> Do not spend time troubleshooting VirtualBox. That is not what the four hours
> are for. A member of staff will resolve it.

---

### 1.2 Confirm Your Toolkit is Ready

Before the clock starts, confirm the following:

```bash
# All four field test suites must pass
pytest field_tests/test_task1.py -v
pytest field_tests/test_task2.py -v
pytest field_tests/test_task3.py -v
pytest field_tests/test_task4.py -v
```

If a suite is failing: fix it now, before the clock starts. A failing tool
is a missing instrument.

```bash
# Confirm target is reachable
ping 172.16.19.200
```

If the target does not respond: check the VM is running and on the
`benji-lab` network. Raise your hand if it remains unreachable.

---

### 1.3 Open Your Submission Files

Open these files now. You will be writing in them throughout the session.

```
vulnerability_hunt/exploit.py
vulnerability_hunt/fix.py
vulnerability_hunt/REPORT.md
docs/build.md
AI_LOG.md
```

They should already contain the scaffolding from Session 4B.
If they are empty, the scaffolds are reproduced in Section 4 of this brief.

Start filling `REPORT.md` and `docs/build.md` the moment the clock starts.
Do not leave them until the end.

---

## SECTION 2 — THE MISSION
### The clock starts when your invigilator says so

| | |
|---|---|
| **Target** | `172.16.19.200` |
| **Time** | Four hours from start signal |
| **GitHub** | Push + `hunt-final` tag before time is called |
| **Moodle** | ZIP submission before time is called — see Phase 4 |

---

### Phase 1 — Diagnose
#### *Up to 10 marks — P2D. Earned in REPORT.md Section 1.*

Run your toolkit against the target. All four tools. In order.

```bash
# Step 1: Map the target
python3 toolkit/task2_network_cartographer/scan.py 172.16.19.200 \
    --ports 1-9000 --threads 200

# Step 2: Enumerate the web layer
python3 toolkit/task4_web_enumerator/web_enum.py http://172.16.19.200

# Step 3: When you have a username — test credentials
python3 toolkit/task3_access_validator/brute.py \
    172.16.19.200 \
    --service ssh \
    --user <username_from_recon> \
    --wordlist field_tests/fixtures/wordlist.txt

# Step 4: When you have access — locate and parse the evidence
python3 toolkit/task1_evidence_collector/log_parser.py <path_to_evidence_log>
```

The tools will tell you what is on this target. Read the output. All of it.
The information you need to proceed is in what the tools return.

**Read before you act. Plan before you code.**

**What earns marks here:** Tool output cited in REPORT.md at each step. Not
"I found a service" — the exact banner, the exact comment text, the exact
success line from brute.py. Evidence earns marks. Assertions do not.

Write your findings in `REPORT.md` as you go — not at the end.
A REPORT.md written in the last fifteen minutes is not a contemporaneous record.
It will be marked as one.

---

### Phase 2 — Exploit
#### *Up to 20 marks — P2E. Earned by running exploit.py and the flag in REPORT.md.*

Write `exploit.py` to retrieve the Flag.

The Flag is a string embedded in a log file on the target system.
It follows this format:

```
COM5413-{DATE}-{HEX}-ETHAN-WAS-HERE-{HASH}
```

It appears once. It is your evidence that you had access to the system.

**The Flag must appear in your REPORT.md and in your `exploit.py` output,
copied exactly — no truncation, no altered case, no added spaces.**

```
FLAG: COM5413-{DATE}-{HEX}-ETHAN-WAS-HERE-{HASH}
```

**Pass level** — credentials passed as arguments:

```bash
python3 vulnerability_hunt/exploit.py \
    --target 172.16.19.200 \
    --user <username> \
    --password <found_password> \
    --keyfile <path_to_evidence_log_on_target>
```

The script connects via SSH using credentials you found manually,
reads the evidence log, extracts and prints the Flag.

**Distinction level** — full chain from wordlist only:

```bash
python3 vulnerability_hunt/exploit.py \
    --target 172.16.19.200 \
    --wordlist field_tests/fixtures/wordlist.txt
```

One command. No pre-found credentials. The script runs the complete chain
without human intervention between steps.

You do not have to reach Distinction level to pass this assessment.
You do have to retrieve the Flag and automate that retrieval in a script.

**What earns marks here:** See the Exploit tier table in the Marking Criteria
document. The tier your script reaches determines your mark band. Within each
tier, marks are awarded for correctness, implementation completeness, and
error handling.

---

### Phase 3 — Fix
#### *Up to 10 marks — P2F. Earned by running fix.py.*

Write `fix.py`. It must complete three actions.

**One: Close the credential exposure.**

The credential storage that allowed you to escalate access should not exist.
Your script removes it. Document what it removes and why in `REPORT.md`.

**Two: Close the initial access vector.**

The account you bruted into should no longer accept the password you found.
Your script changes it. The account must still exist — disabling it entirely
is not a remediation, it is an outage.

**Three: Remove the evidence.**

Benji does not leave traces. The log file containing the Flag must be deleted
from the target before your script exits. After `fix.py` runs, the file must
not exist on the target.

This is not a security remediation. It is the mission objective.
The IMF was never here.

After completing the three actions, `fix.py` must verify all three outcomes
and print the results clearly. You will paste this output into `REPORT.md`.

```bash
python3 vulnerability_hunt/fix.py --target 172.16.19.200
```

**What earns marks here:** See the Fix tier table in the Marking Criteria
document. Pass level requires credentials passed as arguments. Distinction
level requires the script to derive or chain credentials without manual input.
Both exploit.py and fix.py are subject to the Automation Cap — see Section 3.

> **On code structure:** You may implement `fix.py` as a standalone script,
> or import methods from `exploit.py`, or share a common utility module.
> The structure is your choice. What the assessor checks is the outcome:
> `fix.py` runs with its stated arguments and all three actions complete
> without manual intervention.

---

### Phase 4 — Submit
#### *No marks directly — but missing any step here loses marks you already earned.*

Before the session clock stops, complete all of the following. In order.

---

#### Step 4.1 — Complete REPORT.md

REPORT.md must have all four sections filled. The marks each section carries
are stated in brackets.

**Section 1 — Diagnose (10 marks, P2D)**
What your tools found at each step. Tool output cited. The vulnerability class
identified. The attack path described in sequence.

**Section 2 — Exploit (contributes to P2E)**
Your approach to writing exploit.py. The Flag — exact string, unaltered.

**Section 3 — Fix (contributes to P2F)**
What fix.py does at each of the three actions. Why each action closes the
specific vulnerability it targets. The verification output from fix.py pasted
in full.

**Section 4 — Reflection (5 marks, P2X)**
150-200 words. The most significant obstacle you encountered and why it was
one. What you would do differently. How this connects to the vulnerability
management lifecycle. Analysis, not narrative.

**Bonus Section — The Bonus Objective (up to 5 bonus marks)**
If you completed the bonus objective, document it here. See Section 6.

---

#### Step 4.2 — Update AI_LOG.md and build.md

**AI_LOG.md:** Document every substantive AI interaction from today's session.
If you used no AI today: write one line confirming that.
An absent AI_LOG.md is not evidence of not using AI.

**docs/build.md:** Add your Mission section entries. Record what you ran, what
it returned, what you tried that did not work. Written during the session, not after.

---

#### Step 4.3 — Update requirements.txt

```bash
pip freeze > requirements.txt
```

Run this. Commit it. Do not skip it. An incomplete requirements.txt causes
all forty field test marks to fail at the auto-grader.

---

#### Step 4.4 — Commit, tag, and push to GitHub

```bash
git add -A
git commit -m "hunt-final: flag retrieved, fix applied, report complete"
git push origin main
git tag hunt-final
git push origin hunt-final
```

Open GitHub in a browser. Confirm the `hunt-final` tag is visible on your
repository. If it is not there, the tagging step failed — run it again.

Your GitHub repository is assessed for Professional Practice (P1B Criterion 2).
The commit history, tags, and build.md content are all read from GitHub.

---

#### Step 4.5 — Package and submit to Moodle

**The Moodle ZIP is your definitive submission. This is what gets marked.**

The ZIP must contain your complete repository including the `.git` directory.
This preserves your commit history, which is part of your Professional Practice
evidence. A ZIP without `.git` is a ZIP without a commit history.

```bash
# From the directory containing your repository folder:
cd ..
zip -r [YourStudentID]_COM5413_Benji_Protocol.zip COM5413_StudentMain/ --include "COM5413_StudentMain/.git/*" "COM5413_StudentMain/*"
```

Or, if you are in the repository directory itself:

```bash
cd ..
zip -r [YourStudentID]_COM5413_Benji_Protocol.zip ./COM5413_StudentMain/
```

> The `-r` flag recurses into subdirectories including `.git`.
> Confirm the ZIP is not empty before uploading.

Upload the ZIP to the COM5413 Moodle assignment before the session clock stops.

**If the Moodle ZIP and the GitHub repository differ, the Moodle ZIP is marked.**

| What is assessed | Where it comes from |
|---|---|
| Field tests (P1A) | Moodle ZIP |
| Code quality (P1B Criterion 1) | Moodle ZIP |
| Commit history and build.md (P1B Criterion 2) | GitHub repository |
| AI_LOG.md (P1B Criterion 3) | Moodle ZIP |
| exploit.py and fix.py execution | Moodle ZIP |
| REPORT.md | Moodle ZIP |

---

#### Step 4.6 — Final checks before time is called

```
[ ] REPORT.md — all four sections complete, Flag string present and unaltered
[ ] AI_LOG.md — updated, or explicit statement of no use
[ ] docs/build.md — mission log entries written
[ ] requirements.txt — regenerated this session
[ ] git commit — all changes committed
[ ] git push origin main — repository updated
[ ] hunt-final tag — visible on GitHub
[ ] ZIP uploaded to Moodle — file present, not empty, named correctly
```

No commits are accepted after the session closes. No Moodle submissions
accepted after the session closes. The GitHub timestamp on `hunt-final` and
the Moodle submission timestamp are both recorded.

---

## SECTION 3 — WHAT BENJI DOES NOT DO

```
Benji does not use Metasploit.
Benji does not use automated exploit frameworks.
Benji does not paste the mission brief into a chatbot and ask for the solution.
Benji writes the code himself, because he is the one who has to explain it
to Director Hunley when it goes wrong.
```

Formally:

- **No Metasploit.** No automated exploit frameworks. Void on discovery.
- **No undocumented AI.** AI-generated exploit or fix logic not in AI_LOG.md will be referred for academic integrity review. The rule is not "no AI" — it is "document what you used and be able to explain everything you submitted."
- **Code you cannot explain** during a post-session discussion will be flagged. Benji knows why every line does what it does.
- **The Automation Cap.** This applies to both scripts:
  - If the Flag was retrieved manually and `exploit.py` does not automate retrieval when run with its stated arguments, **P2E is capped at 10/20.**
  - If any of the three Fix actions were performed manually and `fix.py` does not execute those actions when run, **P2F is capped at 5/10.**
  - The cap applies to the respective component only. A capped P2E does not affect P2D, P2F, or P2X.

---

## SECTION 4 — SCAFFOLDS
### If exploit.py or fix.py are empty, start here

---

### exploit.py — Pass level scaffold

```python
"""
COM5413 — The Benji Protocol
Operation Nightfall — Exploit Script

Pass level:
    Accepts credentials as arguments. Connects to the target via SSH.
    Reads the evidence log. Extracts and prints the Flag.
    Run as:
        python3 exploit.py --target 172.16.19.200 --user <u> --password <p>

Distinction level:
    Accepts only --target and --wordlist.
    Discovers credentials, retrieves root access, extracts Flag.
    No manual credential input required between steps.
"""
import argparse
import sys

# TODO: import the library you used in Week 3 for SSH connections
# TODO: import the library you need to search text with patterns


def parse_arguments():
    # TODO: implement argparse
    # Required at Pass level: --target, --user, --password
    # Required at Distinction level: --target, --wordlist
    # Use your Week 3 parse_arguments() as a reference
    pass


def connect_ssh(target, user, password):
    """
    Establish an SSH connection to the target.
    Return a connected client object, or None if connection fails.
    You implemented equivalent logic in brute.py — the method is the same.
    """
    # TODO: implement SSH connection
    # On failure: print an error to stderr and return None
    pass


def read_remote_file(client, remote_path):
    """
    Read the contents of a file on the remote host via SSH.
    Return the file contents as a string, or None on error.
    """
    # TODO: use client.exec_command to read the file
    # Handle the case where the file does not exist or is unreadable
    # Return None and print to stderr on failure
    pass


def extract_flag(content):
    """
    Search a string for the COM5413 flag.
    Return the flag token if found, None if not.
    The flag format is stated in Section 2 of this brief.
    Your log_parser.py searches log content for patterns — apply the same method.
    """
    # TODO: implement pattern search using re
    # The flag token begins with COM5413
    # Return the token only — not the entire log line
    pass


def main():
    args = parse_arguments()

    # TODO: connect to the target
    # TODO: read the evidence log from the correct path on the target
    # TODO: extract the flag from the file contents
    # TODO: print the flag in the format: FLAG: <value>
    # TODO: close the connection
    # TODO: exit with code 1 if the flag was not found
    pass


if __name__ == "__main__":
    main()
```

---

### fix.py — Full scaffold

```python
"""
COM5413 — The Benji Protocol
Operation Nightfall — Fix Script

This script must complete three actions via SSH.
What those actions are is stated in Section 2 — Phase 3 of this brief.
The order matters. The verification matters.
The service must still be running when this script exits.
The evidence must not exist on the target when this script exits.

Run as:
    python3 fix.py --target 172.16.19.200
"""
import argparse
import sys

# TODO: import the library you need for SSH connections


def parse_arguments():
    # TODO: implement argparse
    # Required: --target
    # Optional: --password (Pass level — omit at Distinction level)
    # Optional: --user (default should be appropriate for the access level needed)
    pass


def connect_ssh(target, user, password):
    """
    Establish an SSH connection to the target.
    Return a connected client, or None on failure.
    Same pattern as exploit.py — reuse or import.
    """
    # TODO: implement
    pass


def execute_command(client, command):
    """
    Run a shell command on the remote host via SSH.
    Return (stdout, stderr) as decoded strings.
    Print neither automatically — the caller decides what to report.
    """
    # TODO: implement using client.exec_command
    pass


def remove_credential_exposure(client):
    """
    Close the vulnerability that allowed privilege escalation.
    What that vulnerability is, and what command closes it,
    is for you to determine from your REPORT.md Diagnose section.
    The root cause must be addressed — not just the symptom.
    """
    print("[*] Action 1: Removing credential exposure...")
    # TODO: implement
    # TODO: print confirmation of what was done
    pass


def close_access_vector(client):
    """
    Close the initial access point used to enter the system.
    The account must continue to exist after this action.
    Disabling an account is an outage. Changing its credential is a fix.
    """
    print("[*] Action 2: Closing initial access vector...")
    # TODO: implement
    # TODO: choose a replacement credential that is not in a common wordlist
    # TODO: print confirmation
    pass


def remove_evidence(client):
    """
    Delete the evidence log from the target.
    Benji was never here.
    After this function completes, the file must not exist on the target.
    """
    print("[*] Action 3: Removing evidence...")
    # TODO: implement
    # TODO: confirm deletion — do not assume it succeeded
    pass


def verify_remediation(client):
    """
    Confirm all three actions completed and the service is still running.
    Print each result clearly — CONFIRMED or FAILED.
    Paste this output into REPORT.md Section 3.
    """
    print("[*] Verifying remediation state...")
    # TODO: verify the web service is still running
    # TODO: verify the credential exposure has been removed
    # TODO: verify the evidence file no longer exists
    # TODO: print each result: CONFIRMED or FAILED
    pass


def main():
    args = parse_arguments()

    # TODO: connect to the target with the appropriate credentials
    # TODO: call all three action functions in the correct order
    # TODO: call verify_remediation and print the results
    # TODO: close the connection
    # TODO: print final mission status
    pass


if __name__ == "__main__":
    main()
```

---

## SECTION 5 — MARKING FRAMEWORK

All marks come from one of six components. The table below maps each
submission item to the component it contributes to.

| Component | Marks | What earns them |
|---|---|---|
| **P1A — Field Tests** | 40 | pytest runs the same tests you have. (tests passing / total) x 10 per tool. Four tools, 10 marks each. |
| **P1B — Code Quality** | 5 | Assessor reads your code across all four tools. |
| **P1B — Professional Practice** | 5 | Commit history, tags w1-w4 and hunt-final, docs/build.md. |
| **P1B — AI Transparency** | 5 | AI_LOG.md — prompt, output, and verification for every substantive interaction. |
| **P2D — Diagnose** | 10 | REPORT.md Section 1. Evidence of tool output at each step. Four clusters: port recon (2), web enumeration (2), credential acquisition (3), escalation chain (3). |
| **P2E — Exploit** | 20 | Flag HMAC-verified first. Then script tier: Pass (5-10) — credentials as arguments. Merit (11-15) — brute from wordlist. Distinction (16-20) — full chain automated. |
| **P2F — Fix** | 10 | Script tier: Pass (3-5) — credentials as arguments, all three actions, verified. Merit (6-8) — credentials derived or chained. Distinction (9-10) — fully automated, structured output. |
| **P2X — Reflection** | 5 | REPORT.md Section 4. 150-200 words. Specific obstacle. Analytical. Lifecycle connection. |
| **Bonus** | up to +5 | REPORT.md Bonus Section. See Section 6. Total capped at 100. |
| **TOTAL** | **100 (+5)** | |

**On the grade bands:**

- A student who passes all field tests and maximises P1B (55 marks) but scores 0 on Part 2 achieves 55% — a Pass. Merit and Distinction require mission performance.
- The difference between Pass and Merit in Part 1 is robustness, not whether tools work.
- The difference between Merit and Distinction in Part 2 is automation depth, not whether the Flag was retrieved.

The full mark scheme with tier anchors and per-criterion descriptors is in the
**Assessment Marking Criteria** document released alongside this brief.

---

## SECTION 6 — THE BONUS OBJECTIVE

A fully compromised target should be treated as fully compromised. A professional
assessment does not stop at reading the log file — it asks what else is accessible
and what it reveals.

On the assessment target, sufficient access allows you to locate and read the
script responsible for generating the Flag. Inside it are comments. Those comments
contain an Easter egg, and the script itself demonstrates a security vulnerability
class that accounts for a significant proportion of real-world credential exposures.

To claim bonus marks, add a **BONUS** section to `REPORT.md` and document:

1. The full file path of the script you found
2. What the script does, in your own words
3. The specific vulnerability present — named with its correct vulnerability class
4. Why this pattern is dangerous in a production system
5. How an organisation would remediate it correctly — specific, not generic

Do not include the actual key material in `REPORT.md`. Describing what it is
and where it is stored is sufficient.

Marks are awarded from 1 (file found, path stated) to 5 (full analysis with
correct vulnerability class, real-world consequence, and specific remediation).
Total capped at 100.

---

## SECTION 7 — IF YOU ARE STUCK

Four hours is longer than it feels at the start and shorter than it feels at the end.
Stuck is not failed.

**Stuck on Phase 1 — tools not producing useful output:**
Run each tool individually and read the full output. Not the summary — all of it.
The information you need to proceed is in what the tools return. If `web_enum.py`
ran but you did not read the `[COMMENTS]` section: read it now.

**Stuck on finding the username:**
Your `web_enum.py` output contains it. Read the `[COMMENTS]` section.
If the section says "No comments found", check that `Comment` is imported
from `bs4` in your tool and re-run.

**Stuck on the brute force:**
Confirm the username exactly as it appeared in the comments — spacing and case
matter. Confirm the wordlist path is correct. Add a print statement to confirm
attempts are being made.

**Stuck on the database:**
You have SSH access. The MOTD tells you where to look. Read it.

**Stuck on exploit.py:**
The Pass level scaffold is in Section 4. The flag pattern is in Section 2.
`log_parser.py` already contains the regex logic you need — the method
transfers directly.

**Stuck on fix.py:**
Implement one action at a time. Action 3 is the simplest — two lines of
paramiko. Start there. Commit what works. Do not wait until all three actions
work before committing.

**Running out of time:**
Commit what you have. Push. Tag. ZIP and upload to Moodle.
A partial submission with a retrieved Flag, a partial `fix.py`, and a
documented `REPORT.md` is markable. An empty repository is not.
Push early and push often.

---

```
GOOD LUCK IS NOT A STRATEGY.
YOUR TOOLS ARE. USE THEM.

— B. DUNN, IMF TECHNICAL DIVISION
```

---

*COM5413 — The Benji Protocol | Week 5 | Operation Nightfall*
*Assessment document — distribute at session start only*
*Target IP: 172.16.19.200 | Submission tag: hunt-final*

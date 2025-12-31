[🇰🇷 한국어 버전으로 이동](#anti-vm-hardware-encoder-기반-sandbox-회피-기법)

# Anti-VM: Sandbox Evasion Technique Based on Hardware Encoder

> ⚠️ **Disclaimer**
> This document is for educational and security research purposes only. Misusing the techniques described herein on unauthorized systems is illegal, and all responsibility lies with the user.

## Overview: New Anti-VM Approach Using Hardware Functional Gaps

While developing a screen recording program recently, I discovered an interesting phenomenon: **the hardware video encoder functionality of Windows Media Foundation (WMF) does not operate normally in virtual machine (VM) environments.**

While this feature is almost essential in real user PC environments, it is often unsupported in many VMs and automated analysis sandbox environments. In other words, a clear **'functional gap'** exists between real PCs and analysis environments.

I realized this difference could be applied to malware analysis evasion strategies and implemented a simple **PoC loader** to verify it. This document summarizes the technical principles and actual test results of the technique I discovered.

---

## Technical Principle: Environment Determination Based on Functional Execution

Instead of simple environment string comparisons or registry checks, this loader focuses on the question: "Can it actually perform hardware functions?" It uses a two-step verification procedure.

---

### Step 1: Enumerating Hardware Video Encoders (`MFTEnumEx`)

The first step is to check if a **Hardware Accelerated Video Encoder (MFT)** is registered in the system.

| API | Purpose | Key Flag |
| :--- | :--- | :--- |
| `MFTEnumEx` | Enumerate Media Foundation Transforms (MFT) | `MFT_ENUM_FLAG_HARDWARE` |

*   **Typical Real PC**: In environments with a GPU, hardware MFTs are registered, and the enumeration result is **greater than 0**.
*   **VM / Sandbox Environment**: Since most virtual environments do not expose hardware encoders, the result is returned as **0**. → In this case, the loader terminates immediately.

---

### Step 2: Verification Based on Functional Execution (`MFCreateSinkWriterFromURL`)

To prevent evasion by environments that simply spoof API results, the second step attempts to **initialize an actual hardware encoding pipeline**.

The verification flow is as follows:

1.  Set the `MF_READWRITE_ENABLE_HARDWARE_TRANSFORMS` attribute to force hardware acceleration.
2.  Create a `SinkWriter`.
3.  Attempt to start the encoding pipeline by calling `BeginWriting()`.

Even if a hardware MFT appears to exist, **it will inevitably fail at this stage if there is no actual driver or encoder.**

This completes a **functional verification** that is difficult to bypass with simple API hooking or dummy value returns.

---

## 🧪 PoC Test Results

To verify the effectiveness of the technique, I created a loader containing an actual malware payload and uploaded it to a total of **four automated analysis sandboxes, including Any.Run**, for testing.

### Test Results Summary

| Sandbox | Result | Description |
| :--- | :--- | :--- |
| Any.Run | **Success (Evasion)** | Loader judged it as a VM environment and terminated immediately. |
| Platform B | **Success (Evasion)** | Payload not executed. |
| Platform C | **Success (Evasion)** | No malicious activity logs. |
| Platform D | **Success (Evasion)** | Analysis failed. |

In all test environments, the loader recognized the analysis environment as a VM and terminated quietly, and the intended payload was not executed. This shows that **current mainstream automated analysis systems are vulnerable to this technique.**

---

### Test Result Screenshots

> 📌 Below are examples of screens where the loader terminated normally in each sandbox.

*   **Any.Run Result**
    ![Any.Run Result](./images/2025-12-30_211642.png)

*   **Platform B**
    ![Platform B](./images/2025-12-30_211634.png)

*   **Platform C**
    ![Platform C](./images/2025-12-30_211608.png)

---

## Threat Model and Implications

### 1. Exploitation of the Hardware Gap

This technique accurately leverages the **realistic hardware differences** between general user environments and analysis servers.

*   **General User PC**: GPUs and hardware encoders are basically present for video playback and recording.
*   **Analysis Server / Sandbox**: Graphics functionality is minimized due to cost-efficiency and density issues.

This makes it a very suitable condition for info-stealing malware or banking Trojans to **evade security research environments and selectively attack only real users.**

---

### 2. Novelty and High Evasion Rate

*   **Differentiation in Approach**: Unlike existing Anti-VM techniques (CPUID, BIOS strings, registry checks, etc.), the method using WMF's multimedia subsystem is not yet widely known.
*   **High Evasion Rate**: Few sandboxes fully emulate complex media pipelines.

---

### 3. Analysis Difficulty of Rust-based Loader

The loader was written in the **Rust language**. Rust's unique binary structure and compiler optimizations reduce the efficiency of traditional C/C++ based static and dynamic analysis tools, further increasing the difficulty of analysis.

---

## 🛑 Limitations and Future Neutralization Possibilities

This technique is not a silver bullet, and the following limitations exist:

### 1. False Positives in Actual Server Environments

**Physical servers (DCs, file servers, etc.)** without GPUs may be mistaken for VMs. Therefore, it is not suitable for scenarios targeting server infrastructure.

---

### Conclusion

This document is a technical analysis and recommendation for a **new Anti-VM technique based on hardware functional execution** that I personally discovered and implemented.

<br>
<br>

---

# Anti-VM: Hardware Encoder 기반 Sandbox 회피 기법

[🇺🇸 English Version](#anti-vm-sandbox-evasion-technique-based-on-hardware-encoder)

> ⚠️ **면책 조항**
> 본 문서는 교육 및 보안 연구 목적으로만 작성되었습니다. 본문에 기술된 기법을 허가받지 않은 시스템에서 악용하는 것은 불법이며 발생하는 모든 책임은 사용자에게 있습니다.

## 개요: 하드웨어 기능 격차를 이용한 신규 Anti-VM 접근

최근 화면 녹화 프로그램(Screen Recorder)을 개발하는 과정에서 흥미로운 현상을 발견했습니다.
**Windows Media Foundation(WMF)의 하드웨어 비디오 인코더 기능이 가상 머신(VM) 환경에서는 정상적으로 동작하지 않는다**는 점이었습니다.

이 기능은 실제 사용자 PC 환경에서는 거의 필수적으로 제공되지만 많은 VM 및 자동화분석 샌드박스 환경에서는 지원되지 않는 경우가 많았습니다. 
즉, **실제 PC와 분석 환경 사이에 명확한 ‘기능적 격차’가 존재**했던 것입니다.

저는 이 차이를 악성코드 분석회피 기법전략에 적용할 수 있겠다는 아이디어를 얻었고
이를 검증하기 위해 간단한 **PoC 로더**를 구현했습니다.
이 문서는 제가 발견한 기법의 기술적 원리와 실제 테스트 결과를 정리한 것입니다.

---

## 기술적 원리: 기능 수행 여부 기반 환경 판별

이 로더는 단순한 환경 문자열 비교나 레지스트리 검사 대신 “실제로 하드웨어 기능을 수행할 수 있는가?”라는 질문에 초점을 맞춥니다. 이를 위해 두 단계의 검증 절차를 사용합니다.

---

### Step 1: 하드웨어 비디오 인코더 열거 (`MFTEnumEx`)

첫 번째 단계는 시스템에 **하드웨어 가속 비디오 인코더(MFT)** 가 등록되어 있는지를 확인하는 것입니다.

| API | 목적 | 핵심 플래그 |
| :--- | :--- | :--- |
| `MFTEnumEx` | 미디어 변환 필터(MFT) 열거 | `MFT_ENUM_FLAG_HARDWARE` |

*   **일반적인 실제 PC**: GPU가 존재하는 환경에서는 하드웨어 MFT가 등록되어 있으며, 열거 결과는 **0보다 큼**
*   **VM / Sandbox 환경**: 대부분의 가상 환경은 하드웨어 인코더를 노출하지 않기 때문에, 결과가 **0**으로 반환됨 → 이 경우 로더는 즉시 종료

---

### Step 2: 기능 수행 기반 검증 (`MFCreateSinkWriterFromURL`)

단순히 API 결과만 속이는 환경을 방지하기 위해, 두 번째 단계에서는 **실제 하드웨어 인코딩 파이프라인 초기화**를 시도합니다.

검증 흐름은 다음과 같습니다.

1.  `MF_READWRITE_ENABLE_HARDWARE_TRANSFORMS` 속성을 설정하여 하드웨어 가속을 강제
2.  `SinkWriter` 생성
3.  `BeginWriting()` 호출을 통해 인코딩 파이프라인 시작 시도

하드웨어 MFT가 존재하는 것처럼 보이더라도 **실제 드라이버나 인코더가 없으면 이 단계에서 반드시 실패**하게 됩니다.

이로써 단순한 API 후킹이나 더미 값 반환만으로는 우회하기 어려운 **기능적 검증**이 완성됩니다.

---

## 🧪 PoC 테스트 결과

기법의 실효성을 검증하기 위해, 실제 악성코드 페이로드를 포함한 로더를 제작한 후 **Any.Run을 포함한 총 4개의 자동화 분석 샌드박스**에 업로드하여 테스트를 진행했습니다.

### 테스트 결과 요약

| 샌드박스 | 결과 | 설명 |
| :--- | :--- | :--- |
| Any.Run | **우회 성공** | 로더가 VM 환경으로 판단 후 즉시 종료 |
| 플랫폼 B | **우회 성공** | 페이로드 미실행 |
| 플랫폼 C | **우회 성공** | 악성 행위 로그 없음 |
| 플랫폼 D | **우회 성공** | 분석 실패 |

모든 테스트 환경에서 로더는 분석 환경을 VM으로 인식하고 조용히 종료되었으며 의도한 페이로드는 실행되지 않았습니다. 이는 **현재 주류 자동 분석 시스템이 해당 기법에 취약함**을 보여줍니다.

---

### 테스트 결과 스크린샷

> 📌 아래는 각 샌드박스에서 로더가 정상적으로 종료된 화면 예시입니다.

*   **Any.Run 결과**
    ![Any.Run Result](./images/2025-12-30_211642.png)

*   **플랫폼 B**
    ![Platform B](./images/2025-12-30_211634.png)

*   **플랫폼 C**
    ![Platform C](./images/2025-12-30_211608.png)

---

## 위협 모델 및 시사점

### 1. 하드웨어 격차(Hardware Gap)의 악용

이 기법은 일반 사용자 환경과 분석 서버 간의 **현실적인 하드웨어 차이**를 정확히 활용합니다.

*   **일반 사용자 PC**: 영상 재생·녹화를 위해 GPU 및 하드웨어 인코더가 기본적으로 존재
*   **분석 서버 / 샌드박스**: 비용 효율성 및 밀도 문제로 그래픽 기능이 최소화됨

이로 인해 정보 탈취형 악성코드나 뱅킹 트로이목마가 **보안 연구 환경을 회피하고 실제 사용자만 선택적으로 공격**하는 데 매우 적합한 조건이 됩니다.

---

### 2. 신규성과 높은 회피율

*   **접근 방식의 차별성**: 기존 Anti-VM 기법(CPUID, BIOS 문자열, 레지스트리 검사 등)과 달리 WMF의 멀티미디어 서브시스템을 활용한 방식은 아직 널리 알려지지 않음
*   **높은 회피율**: 복잡한 미디어 파이프라인을 완전히 에뮬레이션하는 샌드박스는 드뭄

---

### 3. Rust 기반 로더의 분석 난이도

로더는 **Rust 언어**로 작성되었습니다. Rust 특유의 바이너리 구조와 컴파일러 최적화는 전통적인 C/C++ 기반 정적·동적 분석 도구의 효율을 저하시켜, 분석 난이도를 한층 높입니다.

---

## 🛑 한계점 및 향후 무력화 가능성

이 기법 역시 만능은 아니며, 다음과 같은 한계가 존재합니다.

### 1. 실제 서버 환경 오탐지

GPU가 없는 **물리 서버(DC, 파일 서버 등)** 는 VM으로 오인될 수 있습니다. 따라서 서버 인프라를 주요 공격 대상으로 삼는 시나리오에는 적합하지 않습니다.

---

### 마지막

이 문서는 제가 직접 발견하고 구현한 **하드웨어 기능 수행 여부를 기반으로 한 신규 Anti-VM 기법**에 대한 기술적 분석과 제언입니다.

let previousTexts = [];
let logData = "";
let hasLoggedAtLeastOnce = false;
const DETECTION_INTERVAL = 300; // 밀리초 단위 (ex. 300ms)

console.log("로그 읽기 시작");

const runDetection = () => {
	const currentTexts = [...document.querySelectorAll("span.TranscriptCue_lazy_module_cueText__bc77951f")]
		.map(e => e.textContent.trim());

	// 내용이 없거나 공백만 있는 경우는 건너뛰기
	if (currentTexts.length === 0 || currentTexts.every(t => t === "")) {
		console.log("표시할 텍스트 없음");
		return;
	}

	const currentSerialized = JSON.stringify(currentTexts);
	const previousSerialized = JSON.stringify(previousTexts);

	if (!hasLoggedAtLeastOnce || currentSerialized !== previousSerialized) {
		console.log("변경된 값:", currentTexts);
		logData += currentTexts.join("\n") + "\n";
		previousTexts = [...currentTexts];
		hasLoggedAtLeastOnce = true;
	} else {
		console.log("변경없음");
		logData += currentTexts.join("\n") + "\n";
	}
};

// 주기적 탐지
const intervalId = setInterval(runDetection, DETECTION_INTERVAL);







clearInterval(intervalId);
console.log("최종 로그 저장 시작");

// 파일 저장 함수 (브라우저에서 다운로드)
const saveToFile = (data, filename = "cmmc-result-.txt") => {
	const blob = new Blob([data], {type: "text/plain"});
	const url = URL.createObjectURL(blob);
	const a = document.createElement("a");
	a.href = url;
	a.download = filename;
	a.click();
	URL.revokeObjectURL(url);
};

saveToFile(logData);
console.log("최종 로그 저장 완료");





[...document.querySelectorAll("span.TranscriptCue_lazy_module_cueText__bc77951f")]
		.map(e => e.textContent.trim());
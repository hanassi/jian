let previousTexts = [];
let logData = "";
console.log("로그 읽기 시작");
const intervalId = setInterval(() => {
	// 현재 모든 span.test2 텍스트를 배열로 가져오기
	const currentTexts = [...document.querySelectorAll("span.TranscriptCue_lazy_module_cueText__bc77951f")].map(e => e.innerText);
	
	if (JSON.stringify(currentTexts) !== JSON.stringify(previousTexts)) {
		console.log("변경된 값:", currentTexts);
		previousTexts = [...currentTexts];  // 깊은 복사
		logData += currentTexts.join("\n") + "\n";
	} else {
		console.log("변경없음");
		logData += currentTexts.join("\n") + "\n";
	}

}, 1000);	// 1초마다 체크


setTimeout(() => {
	
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
	
}, 50000); // 30000ms = 30초


//clearInterval(intervalId);
//const currentTexts = [...document.querySelectorAll("span.TranscriptCue_lazy_module_cueText__bc77951f")].map(e => e.textContent.trim());
//console.log(currentTexts);
//const currentTexts = [...document.querySelectorAll("span.TranscriptCue_lazy_module_cueText__bc77951f")].map(e => e.innerText.trim());
//console.log(currentTexts);
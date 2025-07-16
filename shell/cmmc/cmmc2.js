let previousTexts = [];
let logData = "";
let lastChangeTime = Date.now();

const getCurrentTexts = () =>
  [...document.querySelectorAll("span.test2")].map(e => e.innerText).join(" | ");

// 1초마다 체크
const intervalId = setInterval(() => {
  console.log("로그 읽기 시작");
  const currentText = getCurrentTexts();

  if (currentText !== previousTexts.join(" | ")) {
    // 변화가 있을 경우
    previousTexts = currentText.split(" | ");
    lastChangeTime = Date.now(); // 마지막 변경 시간 갱신
    // const logLine = new Date().toISOString() + " - " + currentText + "\n";
    const logLine = currentText + "\n";
    logData += logLine;
    console.log("변경:", logLine.trim());
  }

  // 마지막 변경 후 5초 이상 지났다면 저장하고 종료
  const now = Date.now();
  if (now - lastChangeTime > 10000) {
    clearInterval(intervalId);
    console.log("⚠️ 변화 없음. 로그 저장 후 종료.");

    // 파일 저장 함수
    const saveToFile = (data, filename = "span_test2_log.txt") => {
      const blob = new Blob([data], {type: "text/plain"});
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
    };

    saveToFile(logData);
  }
}, 1000); // 1초마다 체크

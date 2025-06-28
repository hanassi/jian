import os
import xml.etree.ElementTree as ET
import pandas as pd

# XML 폴더 경로
xml_folder = "C:/Users/USER/Documents/@업무/@업무도구/LynSecure Script(주통,전자금융)_250527/01. 주요정보통신기반시설/01. UNIX/1.3 수정/"
# 출력 엑셀 파일
output_excel = "merged_results.xlsx"

# ExcelWriter 열기
with pd.ExcelWriter(output_excel, engine="openpyxl") as writer:
    # 모든 XML 파일 반복
    for filename in os.listdir(xml_folder):
        if filename.endswith(".xml"):
            file_path = os.path.join(xml_folder, filename)
            tree = ET.parse(file_path)
            root = tree.getroot()

            data = []
            for item in root.findall("item"):
                row = {
                    "항목번호": item.findtext("item_num", "").strip(),
                    "제목": item.findtext("item_title", "").strip(),
                    "결과": item.findtext("item_result", "").strip(),
                    "내용": item.findtext("contents", "").strip(),
                    "참고": item.findtext("ref", "").strip()
                }
                data.append(row)

            df = pd.DataFrame(data)

            # 시트명: 파일명에서 확장자 제거
            sheet_name = os.path.splitext(filename)[0]
            df.to_excel(writer, sheet_name=sheet_name[:31], index=False)

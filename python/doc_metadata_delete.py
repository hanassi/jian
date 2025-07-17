import zipfile
import os
import shutil
import tempfile
from docx import Document
from glob import glob

def clean_docx_metadata(input_path, output_path):
    # 임시 폴더 생성
    temp_dir = tempfile.mkdtemp()

    # DOCX는 ZIP 파일이다. 압축 풀기
    with zipfile.ZipFile(input_path, 'r') as zip_ref:
        zip_ref.extractall(temp_dir)

    # 제거 대상 파일 목록 (메타데이터 포함)
    metadata_files = [
        "docProps/core.xml",
        "docProps/app.xml",
        "docProps/custom.xml",
        "customXml/"
    ]

    # 대상 파일 제거
    for meta_file in metadata_files:
        full_path = os.path.join(temp_dir, meta_file)
        if os.path.isfile(full_path):
            os.remove(full_path)
            print(f"[*] Removed file: {meta_file}")
        elif os.path.isdir(full_path):
            shutil.rmtree(full_path)
            print(f"[*] Removed folder: {meta_file}")

    # 새 ZIP으로 다시 압축 (.docx 재생성)
    with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as docx_zip:
        for foldername, subfolders, filenames in os.walk(temp_dir):
            for filename in filenames:
                file_path = os.path.join(foldername, filename)
                arcname = os.path.relpath(file_path, temp_dir)
                docx_zip.write(file_path, arcname)

    # 임시 디렉토리 삭제
    shutil.rmtree(temp_dir)
    print(f"Cleaned metadata saved to: {output_path}")

# 사용 예시
if __name__ == "__main__":
    #input_docx = "sample.docx"  # 원본 파일
    #output_docx = "sample_cleaned.docx"  # 메타데이터 제거 후 저장 파일
    #clean_docx_metadata(input_docx, output_docx)
    path = "C:/Users/Jian/Documents/@DEV/cmmc/*.docx"
    docx_list = glob(path)
    for file in docx_list:
        print(f"[*] 파일 클리닝 시작 - {file}")
        clean_docx_metadata(file, file)

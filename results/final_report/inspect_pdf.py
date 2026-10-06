from pathlib import Path
import json
import pymupdf
from PIL import Image, ImageOps, ImageDraw

root=Path.cwd();out=root/'results/final_report';renders=out/'pdf_review';renders.mkdir(exist_ok=True)
pdf=pymupdf.open(root/'reports/CSE_CIC_IDS2018_Security_AI_Final_Experiment_Report.pdf')
rows=[]
for i,page in enumerate(pdf):
    pix=page.get_pixmap(matrix=pymupdf.Matrix(1.5,1.5),alpha=False)
    pix.save(renders/f'page_{i+1:02d}.png')
    text=page.get_text();bad=[]
    for block in page.get_text('dict')['blocks']:
        if block['type']!=0:continue
        for line in block['lines']:
            for span in line['spans']:
                x0,y0,x1,y1=span['bbox']
                if x0<45 or x1>page.rect.width-45 or y0<35 or (y1>page.rect.height-48 and y0<page.rect.height-48):
                    # Footer is below the body; distinguish it from overflow.
                    if y0<page.rect.height-45:bad.append(span['text'])
    rows.append(dict(page=i+1,chars=len(text),images=len(page.get_images()),replacement_characters=text.count('\ufffd'),bounds_issues=bad,title=' | '.join(text.splitlines()[2:6])))
for start in range(0,len(pdf),6):
    sheet=Image.new('RGB',(1500,2240),'#dce3ec');draw=ImageDraw.Draw(sheet)
    for j in range(6):
        n=start+j
        if n>=len(pdf):break
        im=Image.open(renders/f'page_{n+1:02d}.png');im.thumbnail((480,1060))
        x=(j%3)*500+10;y=(j//3)*1120+35
        sheet.paste(im,(x,y));draw.text((x,y-23),f'Page {n+1:02d}',fill='#142d4e')
    sheet.save(renders/f'contact_{start//6+1:02d}.png')
report=dict(pages=len(pdf),page_size='A4 portrait',all_pages_rendered=True,korean_text_present=all(any('\uac00'<=c<='\ud7a3' for c in p.get_text()) for p in pdf),pages_detail=rows)
(out/'pdf_quality_check.json').write_text(json.dumps(report,ensure_ascii=False,indent=2))
print(json.dumps(dict(pages=len(pdf),replacement_characters=sum(r['replacement_characters'] for r in rows),bounds_issues=[r for r in rows if r['bounds_issues']]),ensure_ascii=False))

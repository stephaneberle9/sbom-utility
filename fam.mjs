import fs from 'fs';
const map={'EPL-1.0':'EPL-1.0','EPL-2.0':'EPL-2.0','MPL-1.0':'MPL-1.0','MPL-1.1':'MPL-1.1','MPL-2.0':'MPL-2.0'};
for(const f of ['license.json','resources/config/license.json']){
  const lines=fs.readFileSync(f,'utf8').split('\n');let n=0;
  for(let i=0;i<lines.length;i++){const m=/^            "id": "([^"]+)",$/.exec(lines[i]);
    if(m&&map[m[1]]){for(let j=i;j<i+8;j++){if(/^            "family": /.test(lines[j])){lines[j]=`            "family": "${map[m[1]]}",`;n++;break}}}}
  fs.writeFileSync(f,lines.join('\n'));JSON.parse(fs.readFileSync(f,'utf8'));console.log(f,n)}

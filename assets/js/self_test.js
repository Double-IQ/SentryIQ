const configNode=document.getElementById('sentryiq-self-test-data');
const config=JSON.parse(configNode.textContent);
const tests=config.tests;
const csrf=config.csrf;
let reportData={diagnosticBuild:config.diagnosticBuild,serverChecks:config.serverChecks,browserChecks:[]};
function esc(v){return String(v??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[m]));}
async function checkOne(test){
    const started=performance.now();
    const expectedRequestedPath=new URL(test.url,location.href).pathname;
    try{
        const r=await fetch(test.url,{credentials:'same-origin',cache:'no-store',redirect:'follow',headers:{'Accept':'*/*'}});
        const ms=Math.round(performance.now()-started);
        const contentType=r.headers.get('content-type')||'';
        const statusOk=Number.isInteger(r.status)&&r.status>=200&&r.status<300;
        const finalUrl=new URL(r.url,location.href);
        const expectedFinalPath=test.expectedFinalPath?new URL(test.expectedFinalPath,location.href).pathname:expectedRequestedPath;
        const finalPathOk=finalUrl.pathname===expectedFinalPath;
        const contentTypeOk=!test.expectedContentType||contentType.toLowerCase().startsWith(test.expectedContentType.toLowerCase());

        let stylesheetOk=true;
        let stylesheetDetail=null;
        if(statusOk&&(test.expectedStylesheet||test.parseCss)){
            try{
                const stylesheetUrl=test.expectedStylesheet||test.url;
                const sr=await fetch(stylesheetUrl,{credentials:'same-origin',cache:'no-store',redirect:'follow',headers:{'Accept':'text/css,*/*'}});
                const st=sr.headers.get('content-type')||'';
                const styleText=await sr.text();
                stylesheetDetail={status:sr.status,statusOk:sr.status>=200&&sr.status<300,contentType:st,contentTypeOk:st.toLowerCase().startsWith('text/css'),url:sr.url,bytes:styleText.length,parseOk:false,ruleCount:0,contracts:[]};
                stylesheetOk=stylesheetOk&&stylesheetDetail.statusOk&&stylesheetDetail.contentTypeOk&&styleText.trim().length>0;
                if(stylesheetOk){
                    // Parse the fetched same-origin stylesheet without injecting an inline
                    // <style> block, which the production style-src 'self' CSP correctly blocks.
                    const parsedSheet=new CSSStyleSheet();
                    parsedSheet.replaceSync(styleText);
                    const rules=Array.from(parsedSheet.cssRules);
                    stylesheetDetail.ruleCount=rules.length;
                    stylesheetDetail.parseOk=rules.length>0;
                    stylesheetOk=stylesheetOk&&rules.length>0;

                    for(const contract of (test.expectedCssContracts||[])){
                        const declarationProperty=contract.property.replace(/[A-Z]/g,m=>'-'+m.toLowerCase());
                        let actual='';
                        let found=false;
                        for(const rule of rules){
                            if(rule.type!==CSSRule.STYLE_RULE||typeof rule.selectorText!=='string')continue;
                            if(!rule.selectorText.split(',').map(v=>v.trim()).includes(contract.selector))continue;
                            const value=rule.style.getPropertyValue(declarationProperty).trim();
                            if(value){actual=value;found=true;}
                        }
                        const ok=contract.value!==undefined?actual===contract.value:(contract.not!==undefined?actual!==contract.not:actual!=='');
                        stylesheetDetail.contracts.push({...contract,actual,ok});
                        if(!ok)stylesheetOk=false;
                    }
                    
                }
            }catch(error){
                stylesheetOk=false;
                stylesheetDetail={error:String(error&&error.message||error)};
            }
        }

        let bodySignatureOk=true;
        let bodyBytes=null;
        const htmlReferenceResults=[];
        if(Array.isArray(test.expectedMagic)){
            const buffer=await r.arrayBuffer();
            bodyBytes=new Uint8Array(buffer);
            bodySignatureOk=test.expectedMagic.every((value,index)=>bodyBytes[index]===value);
        }else if(test.type!=='asset'){
            const textBody=await r.text();
            bodySignatureOk=textBody.length>0;
            if(bodySignatureOk&&Array.isArray(test.requiredHtmlRefs)){
                const doc=new DOMParser().parseFromString(textBody,'text/html');
                for(const ref of test.requiredHtmlRefs){
                    let match=null;
                    const matchesReference=value=>{
                        if(ref.value){
                            try{return new URL(value,r.url).pathname===new URL(ref.value,r.url).pathname;}
                            catch{return false;}
                        }
                        return !!ref.prefix&&value.startsWith(ref.prefix);
                    };
                    if(ref.tag==='link')match=Array.from(doc.querySelectorAll('link')).find(el=>matchesReference(el.getAttribute('href')||''))||null;
                    else if(ref.tag==='script')match=Array.from(doc.querySelectorAll('script[src]')).find(el=>matchesReference(el.getAttribute('src')||''))||null;
                    else if(ref.tag==='img')match=Array.from(doc.querySelectorAll('img[src]')).find(el=>matchesReference(el.getAttribute('src')||''))||null;
                    const found=!!match;
                    const actualUrl=match?(match.getAttribute(ref.tag==='link'?'href':'src')||''):'';
                    // HTML asset references are relative to the page being tested, not the diagnostic page.
                    const resolvedUrl=actualUrl?new URL(actualUrl,r.url).href:'';
                    let urlCheck=null;
                    if(found){
                        try{
                            const ar=await fetch(resolvedUrl,{credentials:'same-origin',cache:'no-store',redirect:'follow',headers:{'Accept':'*/*'}});
                            const at=ar.headers.get('content-type')||'';
                            const expectedType=ref.tag==='link'?'text/css':(ref.tag==='script'?'text/javascript':'image/');
                            const typeOk=ref.tag==='img'
                                ?at.toLowerCase().startsWith('image/')
                                :(ref.tag==='script'
                                    ?(at.toLowerCase().startsWith('text/javascript')||at.toLowerCase().startsWith('application/javascript'))
                                    :at.toLowerCase().startsWith(expectedType));
                            urlCheck={status:ar.status,statusOk:ar.status>=200&&ar.status<300,contentType:at,contentTypeOk:typeOk,finalUrl:ar.url};
                            if(!(urlCheck.statusOk&&urlCheck.contentTypeOk))bodySignatureOk=false;
                        }catch(error){
                            urlCheck={status:0,statusOk:false,contentType:'',contentTypeOk:false,finalUrl:'',error:String(error&&error.message||error)};
                            bodySignatureOk=false;
                        }
                    }else{
                        bodySignatureOk=false;
                    }
                    htmlReferenceResults.push({...ref,found,actualUrl,resolvedUrl,urlCheck});
                }
            }
        }

        const allOk=statusOk&&contentTypeOk&&finalPathOk&&stylesheetOk&&bodySignatureOk;
        return {...test,ok:allOk,status:r.status,statusText:r.statusText,finalUrl:r.url,timeMs:ms,contentType,stylesheetDetail,htmlReferenceResults,
            checks:{tested:true,statusOk,contentTypeOk,finalPathOk,stylesheetOk,bodySignatureOk,expectedFinalPath}};
    }catch(e){
        return {...test,ok:false,status:0,statusText:String(e&&e.message||e),finalUrl:'',timeMs:Math.round(performance.now()-started),contentType:'',
            stylesheetDetail:null,htmlReferenceResults:[],
            checks:{tested:true,statusOk:false,contentTypeOk:false,finalPathOk:false,stylesheetOk:false,bodySignatureOk:false,expectedFinalPath:expectedRequestedPath}};
    }
}
async function runChecks(){
    const tbody=document.querySelector('#browser-table tbody');
    tbody.innerHTML='';
    document.querySelector('#browser-summary').textContent='Running checks…';
    const out=[];
    for(const test of tests){
        if(test.type==='not-tested'){
            const item={...test,ok:null,status:null,statusText:'NOT TESTED',finalUrl:'',timeMs:0,contentType:'',checks:{tested:false}};
            out.push(item);
            const tr=document.createElement('tr');
            tr.innerHTML='<td>'+esc(item.type)+'</td><td><code>'+esc(item.url)+'</code></td><td class="warn">NOT TESTED</td><td>—</td><td>—</td><td>'+esc(item.reason||'')+'</td>';
            tbody.appendChild(tr);
            continue;
        }
        const item=await checkOne(test);
        out.push(item);
        const tr=document.createElement('tr');
        const statusLabel=item.ok===true?'PASS':'FAIL';
        const statusClass=item.ok===true?'ok':'bad';
        const detail=item.stylesheetDetail?'<br><small>'+esc(JSON.stringify(item.stylesheetDetail))+'</small>':'';
        tr.innerHTML='<td>'+esc(item.type)+'</td><td><code>'+esc(item.url)+'</code></td><td class="'+statusClass+'">'+statusLabel+'</td><td>'+esc(item.status)+' '+esc(item.statusText)+'</td><td>'+esc(item.contentType)+'</td><td>'+esc(item.finalUrl)+detail+'</td>';
        tbody.appendChild(tr);
    }
    reportData.browserChecks=out;
    const failed=out.filter(x=>x.ok===false);
    const notTested=out.filter(x=>x.ok===null);
    document.querySelector('#browser-summary').innerHTML=failed.length
        ? '<span class="bad">'+failed.length+' browser health check(s) failed.</span>'+(notTested.length?' <span class="warn">'+notTested.length+' not tested.</span>':'')
        : '<span class="ok">All '+out.filter(x=>x.ok!==null).length+' browser health checks passed.</span>'+(notTested.length?' <span class="warn">'+notTested.length+' not tested.</span>':'');
    document.querySelector('#report').textContent=JSON.stringify(reportData,null,2);
    try{await fetch(location.pathname,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({diagnostic_log:JSON.stringify(reportData),csrf_token:csrf}).toString()});}catch(_){}
}


document.querySelector('#run').addEventListener('click',runChecks);
document.querySelector('#copy').addEventListener('click',async()=>{try{await navigator.clipboard.writeText(document.querySelector('#report').textContent);document.querySelector('#copy').textContent='Copied';setTimeout(()=>document.querySelector('#copy').textContent='Copy report',1400);}catch(_){}});

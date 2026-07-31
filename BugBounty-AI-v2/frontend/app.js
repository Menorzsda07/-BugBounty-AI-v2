const chat = document.getElementById('chat');
const composer = document.getElementById('composer');
const promptBox = document.getElementById('prompt');
let conversationId = null;

function escapeHtml(value){return value.replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));}
function addUser(text){chat.insertAdjacentHTML('beforeend',`<div class="message user"><div class="bubble">${escapeHtml(text)}</div></div>`);scroll();}
function addTyping(){const id='typing-'+Date.now();chat.insertAdjacentHTML('beforeend',`<div id="${id}" class="message assistant"><div class="bot-avatar">◆</div><div class="bubble muted">Validando escopo e preparando o plano…</div></div>`);scroll();return id;}
function coverageChips(plan){return plan.map(x=>`<span class="chip">${escapeHtml(x.name)}</span>`).join('');}
function investigationCard(inv){
 const finding=inv.findings?.[0];
 const evidence=(finding?.evidence||[]).map(e=>`<div class="evidence"><strong>${escapeHtml(e.type.toUpperCase())}: ${escapeHtml(e.filename)}</strong><div>${escapeHtml(e.description)}</div><code>SHA-256: ${escapeHtml(e.sha256||'n/a')}</code></div>`).join('');
 return `<div class="progress-card"><div class="progress-head"><div><strong>Investigação ${escapeHtml(inv.id)}</strong><div class="muted">${escapeHtml(inv.target)}</div></div><strong>${inv.progress}%</strong></div><div class="progress-bar"><span></span></div><div class="timeline">${inv.timeline.map(t=>`<span>${escapeHtml(t)}</span>`).join('')}</div><div class="coverage">${coverageChips(inv.plan)}</div></div>
 ${finding?`<div class="finding-card"><h3>${escapeHtml(finding.title)}</h3><div class="muted">${escapeHtml(finding.summary)}</div><div class="meta-grid"><div class="meta"><small>Status</small><strong class="state">${escapeHtml(finding.state)}</strong></div><div class="meta"><small>Severidade</small><strong class="severity-info">${escapeHtml(finding.severity)}</strong></div><div class="meta"><small>Confiança</small><strong>${finding.confidence}%</strong></div><div class="meta"><small>Endpoint</small><strong>${escapeHtml(finding.endpoint)}</strong></div></div><h4>Resultado observado</h4><p>${escapeHtml(finding.observed_result)}</p><h4>Impacto</h4><p>${escapeHtml(finding.impact)}</p><h4>Evidências preservadas</h4><div class="evidence-list">${evidence}</div><h4>Correção sugerida</h4><ul>${finding.remediation.map(r=>`<li>${escapeHtml(r)}</li>`).join('')}</ul><div class="action-row"><button onclick="downloadReport('${inv.id}')">📄 Abrir relatório</button><button>🧾 Ver evidências</button><button>↻ Continuar investigação</button></div></div>`:''}`;
}
function addAssistant(data, typingId){document.getElementById(typingId)?.remove();chat.insertAdjacentHTML('beforeend',`<div class="message assistant"><div class="bot-avatar">◆</div><div class="bubble"><div>${escapeHtml(data.reply).replace(/\n/g,'<br>')}</div>${data.investigation?investigationCard(data.investigation):''}</div></div>`);scroll();}
function addError(msg, typingId){document.getElementById(typingId)?.remove();chat.insertAdjacentHTML('beforeend',`<div class="message assistant"><div class="bot-avatar">◆</div><div class="bubble">Não consegui acessar o backend. Abra esta prévia pelo servidor FastAPI ou use o arquivo preview-iphone.html para a demonstração offline.<br><small class="muted">${escapeHtml(msg)}</small></div></div>`);scroll();}
function scroll(){requestAnimationFrame(()=>chat.scrollTop=chat.scrollHeight)}
async function send(text){if(!text.trim())return;addUser(text);promptBox.value='';const typing=addTyping();try{const r=await fetch('/api/chat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message:text,conversation_id:conversationId})});if(!r.ok)throw new Error(await r.text());const data=await r.json();conversationId=data.conversation_id;addAssistant(data,typing);}catch(e){addError(String(e),typing)}}
composer.addEventListener('submit',e=>{e.preventDefault();send(promptBox.value)});
promptBox.addEventListener('input',()=>{promptBox.style.height='auto';promptBox.style.height=Math.min(promptBox.scrollHeight,150)+'px'});
document.querySelectorAll('[data-prompt]').forEach(b=>b.addEventListener('click',()=>send(b.dataset.prompt)));
document.getElementById('menuBtn').addEventListener('click',()=>document.querySelector('.sidebar').classList.toggle('open'));
window.downloadReport=id=>window.open(`/api/investigations/${id}/report`,'_blank');

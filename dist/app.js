import { LocalHistoryManager } from './local-history.mjs';

const $ = id => document.getElementById(id);
const colors = ['#5de0ba','#7da9ff','#f6c56f','#ec91b0','#b1a2f7','#7fd0df','#bed985','#ff9c77'];
const localHistory = new LocalHistoryManager();
const mapStyles = { dark: 'https://tiles.openfreemap.org/styles/dark', detailed: 'https://tiles.openfreemap.org/styles/liberty' };
let current, map, account, hostTab = 'subdomains', historyTab = 'local', cloudHistory = [], indicators = [];
const el = (tag, value, className) => { const n = document.createElement(tag); if (value != null) n.textContent = String(value); if (className) n.className = className; return n; };
const text = (id, value, fallback = 'Unavailable') => $(id).textContent = value == null || value === '' ? fallback : String(value);
const clear = id => $(id).replaceChildren();
const time = value => value ? new Date(value).toLocaleString() : 'Unknown';
const area = p => [p?.city,p?.region,p?.country].filter(Boolean).join(', ') || 'No named area';
const status = (id, msg, error = false) => { const n = $(id); n.textContent = msg; n.hidden = !msg; n.classList.toggle('error', error); };
const row = (body, cells) => { const tr = el('tr'); cells.forEach(v => tr.append(el('td',v))); body.append(tr); return tr; };
const filename = () => (current?.input?.domain || current?.selectedIp || 'investigation').replace(/[^a-z0-9.-]/gi,'_').slice(0,80);
const link = (url, label) => { if (!url?.startsWith('https://')) return el('span',label); const a=el('a',label,'evidence-link'); a.href=url; a.target='_blank'; a.rel='noopener noreferrer'; return a; };
function download(blob,name) { const url=URL.createObjectURL(blob), a=el('a'); a.href=url; a.download=name; document.body.append(a); a.click(); a.remove(); setTimeout(()=>URL.revokeObjectURL(url),10000); }
async function api(path, options) {
  const response=window.IP_INSIGHT_STATIC ? await (await import('./browser-api.mjs')).browserApi(path,options) : await fetch(path,options);
  if(!(response.headers.get('content-type') || '').includes('application/json')) {
    throw new Error('Site access may have expired. Reload this page and sign in with ChatGPT, then try again.');
  }
  const data=await response.json();
  if(!response.ok) throw new Error(data.error || 'Request failed.');
  return data;
}
const post = (path,body={}) => api(path,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
async function query(domain,ip,summary=false) { const params=new URLSearchParams(); if(domain)params.set('domain',domain); if(ip)params.set('ip',ip); if(summary)params.set('summary','1'); return api('/api/investigate?'+params); }

let gisPromise;
function loadGIS() { if (!gisPromise) gisPromise=new Promise((resolve,reject)=>{ const script=document.createElement('script'); script.src='https://accounts.google.com/gsi/client'; script.async=true; script.onload=resolve; script.onerror=()=>reject(new Error('Google sign-in could not load.')); document.head.append(script); }); return gisPromise; }
async function offerGoogle() {
  try { const {nonce}=await post('/api/auth/challenge'); await loadGIS();
    google.accounts.id.initialize({client_id:account.clientId,nonce,callback:async response=>{
      try { await post('/api/auth/google',{credential:response.credential}); status('history-status','Google connected. New investigations will be saved.'); await refreshAccount(); }
      catch(error) { status('history-status',error.message,true); await offerGoogle(); }
    }});
    google.accounts.id.renderButton($('google-button'),{theme:'filled_black',size:'medium',text:'signin_with'});
  } catch(error) { status('history-status',error.message,true); }
}
async function refreshAccount() {
  try { account=await api('/api/me'); } catch { account=null; }
  clear('google-button'); $('google-signout').hidden=!account?.googleSignedIn;
  text('account-status',window.IP_INSIGHT_STATIC ? 'GitHub Pages · browser-only' : account?.localOnly ? 'Local browser' : account?.googleSignedIn ? account.name || account.email || 'Google connected' : account?.siteSignedIn ? 'Site access active' : 'Site sign-in required');
  $('history-cloud-tab').disabled=!account?.googleSignedIn;
  if(!account?.googleSignedIn && historyTab==='cloud') historyTab='local';
  renderHistory();
  if(account?.googleSignedIn) return refreshHistory();
  if(account?.siteSignedIn && account?.storageAvailable && account.clientId) await offerGoogle();
}
async function refreshHistory() {
  try { const {items}=await api('/api/history'); cloudHistory=items; renderHistory();
  } catch(error) { status('history-status',error.message,true); }
}
function renderHistory() {
  const local=historyTab==='local', items=local ? localHistory.list() : cloudHistory;
  $('history-local-tab').classList.toggle('active',local);
  $('history-cloud-tab').classList.toggle('active',!local);
  $('history-local-tab').setAttribute('aria-selected',String(local));
  $('history-cloud-tab').setAttribute('aria-selected',String(!local));
  text('history-count',items.length);
  text('history-intro',local ? 'Recent investigations saved on this browser.' : 'Investigations saved to your Google-connected Site account.');
  clear('history-list');
  if(!items.length) $('history-list').append(el('p',local ? 'Your next investigation will appear here.' : 'No Google history yet.','history-empty'));
  items.forEach(item=>{ const b=el('button',null,'history-item'); b.type='button'; b.append(el('strong',item.target),el('span',`${item.selected_ip || 'No IP'} · ${time(item.created_at)}`)); b.addEventListener('click',()=>local ? openLocalHistory(item.id) : openHistory(item.id)); $('history-list').append(b); });
}
function openLocalHistory(id) { const record=localHistory.get(id); if(!record) return status('history-status','This browser no longer has that investigation.',true); current={...record.result,historyId:undefined,localHistoryId:id}; $('case-notes').value=record.notes || ''; render(); $('results').scrollIntoView({behavior:'smooth'}); }
async function openHistory(id) { try { const data=await api('/api/history/'+id); current={...data.result,historyId:id,historyStatus:'saved'}; $('case-notes').value=data.notes || ''; render(); $('results').scrollIntoView({behavior:'smooth'}); } catch(error) { status('history-status',error.message,true); } }
$('history-local-tab').addEventListener('click',()=>{historyTab='local';renderHistory();});
$('history-cloud-tab').addEventListener('click',()=>{if(!account?.googleSignedIn)return;historyTab='cloud';renderHistory();});
$('google-signout').addEventListener('click',async()=>{ try { await post('/api/auth/signout'); window.google?.accounts?.id?.disableAutoSelect(); await refreshAccount(); status('history-status','Google disconnected. Existing history remains on this Site.'); } catch(error) { status('history-status',error.message,true); } });

async function runInvestigation() {
  const domain=$('domain-input').value.trim(), ip=$('ip-input').value.trim();
  if(!domain && !ip) return status('status','Enter a website or public IP address.',true);
  $('submit-button').disabled=true; status('status','Checking DNS, location providers, routing, registration, and public host records…');
  try { current=await query(domain,ip); updateAssetChanges(); const saved=localHistory.save(current); if(saved.id)current.localHistoryId=saved.id; $('case-notes').value=''; $('web-authorized').checked=false; render(); renderHistory(); status('status','Investigation complete. Review the source log and location limits.'); $('results').scrollIntoView({behavior:'smooth'}); if(current.historyId) refreshHistory(); }
  catch(error) { status('status',error.message,true); } finally { $('submit-button').disabled=false; }
}
$('investigate-form').addEventListener('submit',e=>{e.preventDefault();runInvestigation();});
$('example-button').addEventListener('click',()=>{$('domain-input').value='example.com';$('ip-input').value='';runInvestigation();});

function updateAssetChanges() {
  const domain=current?.input?.domain;
  if(!domain || !current.subdomains)return;
  const previous=localHistory.read().find(record=>record.id!==current.localHistoryId && record.result?.input?.domain===domain && record.result?.subdomains);
  if(!previous){current.assetChanges=null;return;}
  const known=new Set((previous.result.subdomains.items || []).map(item=>item.name));
  current.assetChanges={previousAt:previous.created_at,newNames:(current.subdomains.items || []).filter(item=>!known.has(item.name)).map(item=>item.name)};
}
function persistCurrentSnapshot(){
  if(!current)return false;
  if(current.localHistoryId && localHistory.updateResult(current.localHistoryId,current))return true;
  const saved=localHistory.save(current);
  if(!saved.id)return false;
  current.localHistoryId=saved.id;renderHistory();text('save-state','Updated snapshot saved on this browser');return true;
}

function render() {
  const r=current; $('results').hidden=false;
  status('deep-status',''); status('exposure-status',''); status('dns-status',''); status('web-status','');
  text('result-target',r.input.domain || r.selectedIp || 'Unresolved target');
  text('result-relation',r.input.domain && r.input.requestedIp ? r.domainResolvesToSelectedIp ? 'The supplied IP appears in current DNS answers.' : 'The supplied IP was not returned in current DNS answers.' : r.input.domain ? `${r.resolvedIps.length} current DNS addresses found. Each may serve this site.` : 'Public IP investigation');
  text('result-time','Completed '+time(r.completedAt)); text('result-source-count',`${r.evidence.length} source checks`);
  text('save-state',r.localHistoryId && r.historyId ? 'Saved here and to Google history' : r.localHistoryId ? 'Saved on this browser' : r.historyId ? 'Saved to Google history' : 'Export to keep a copy');
  renderIps(); renderLocationControls(); renderNetwork(); renderThreat(); renderExposure(); renderDnsPosture(); renderWebPosture(); renderHosts(); renderEvidence(); renderMatches();
}
function renderIps() {
  const mapped=new Map((current.ipLocations || []).map(x=>[x.ip,x.location]));
  const all=[...new Set([current.selectedIp,...(current.resolvedIps || [])].filter(Boolean))];
  text('ips-note',`${mapped.size} of ${all.length} current public addresses mapped.${current.ipLocationsTruncated ? ` The first ${current.limits?.mappedIps || 8} were enriched; investigate any remaining IP separately.` : ''} DNS answers can change by resolver, place, and time.`);
  clear('ips-body'); if(!all.length) row($('ips-body'),['No public address resolved','—','—','—','']);
  all.forEach(ip=>{ const loc=mapped.get(ip), tr=row($('ips-body'),[ip,loc?.agreement==='low agreement' ? 'Conflicting reports' : loc?.center ? area(loc.center) : 'Not mapped',loc?.agreement || '—',loc?.radiusKm == null ? 'Unknown' : loc.radiusKm+' km','']); const b=el('button',loc ? 'Show on map' : 'Investigate IP','text-button'); b.type='button'; b.addEventListener('click',()=>{ if(loc){$('map-ip-filter').value=ip;renderLocations();$('map').scrollIntoView({behavior:'smooth',block:'center'});}else{$('domain-input').value='';$('ip-input').value=ip;runInvestigation();} }); tr.lastChild.append(b); });
}
function renderLocationControls() {
  const previous=$('map-ip-filter').value; clear('map-ip-filter'); const all=el('option','All mapped IPs'); all.value='all'; $('map-ip-filter').append(all);
  (current.ipLocations || []).forEach(item=>{const o=el('option',item.ip);o.value=item.ip;$('map-ip-filter').append(o);});
  $('map-ip-filter').value=[...$('map-ip-filter').options].some(x=>x.value===previous) ? previous : 'all'; renderLocations();
}
$('map-ip-filter').addEventListener('change',renderLocations);
$('map-style').addEventListener('change',()=>{if(current)renderMap(visibleLocations());});
function visibleLocations() { const selected=$('map-ip-filter').value; return (current.ipLocations || []).filter(x=>x.location?.providers?.length && (selected==='all' || selected===x.ip)); }
function renderLocations() {
  const items=visibleLocations(), count=items.reduce((sum,x)=>sum+x.location.providers.length,0), focused=items.length===1 ? items[0] : null;
  text('location-count',`${count} provider-reported points across ${items.length} IPs`);
  text('map-point-count',`${count} source point${count===1?'':'s'} · ${items.length} IP${items.length===1?'':'s'}`);
  text('consensus-area',focused?.location.agreement === 'low agreement' ? 'No clear consensus' : focused ? area(focused.location.center) : `${items.length} IP areas`);
  text('consensus-detail',focused ? focused.location.agreement === 'low agreement' ? `${focused.ip} · sources disagree widely. Neither point is a defensible most-likely location.` : `${focused.ip} · ${focused.location.nearestConsensusSource || 'single source'} is closest to the other reports · ${focused.location.agreement}. This is a reported network area.` : 'Select an IP to compare its source reports. Multiple DNS IPs can all serve the same site.');
  text('radius-value',focused?.location.radiusKm == null ? 'Unknown' : focused.location.radiusKm+' km');
  const statedRadius = focused?.location.providers.find(p=>p.reportedAccuracyKm != null);
  text('radius-description',focused ? `${focused.location.explanation || 'A radius needs two provider coordinates.'}${statedRadius ? ` ${statedRadius.name} separately reports an ${statedRadius.reportedAccuracyKm} km accuracy radius around its point.` : ''}` : 'Select one IP to see its provider spread circle. The map shows each reported point.');
  clear('location-list'); if(!count) $('location-list').append(el('p','No provider returned coordinates for this selection.','muted'));
  items.forEach(item=>{ const color=colors[current.ipLocations.findIndex(x=>x.ip===item.ip)%colors.length]; item.location.providers.forEach(p=>{const b=el('button',null,'location-item'),top=el('div',null,'location-item-top'),swatch=el('i',null,'ip-swatch');b.type='button';swatch.style.background=color;top.append(swatch,el('span',item.ip+' · '+p.name));b.append(top,el('strong',area(p)),el('small',`${p.latitude.toFixed(3)}°, ${p.longitude.toFixed(3)}° · ${time(p.checkedAt)}${p.reportedAccuracyKm == null ? '' : ` · source accuracy radius ${p.reportedAccuracyKm} km`}`));b.addEventListener('click',()=>map?.flyTo({center:[p.longitude,p.latitude],zoom:9}));$('location-list').append(b);}); });
  renderMap(items);
}
function circle(center,radiusKm) { const coords=[],lat=center.latitude*Math.PI/180; for(let i=0;i<=64;i++){const angle=i*2*Math.PI/64;coords.push([center.longitude+radiusKm/(111.32*Math.max(.05,Math.cos(lat)))*Math.cos(angle),center.latitude+radiusKm/111.32*Math.sin(angle)]);} return {type:'Feature',geometry:{type:'Polygon',coordinates:[coords]},properties:{}}; }
function addMarker(point,color,title,consensus=false) { const pin=el('div',null,consensus ? 'map-marker consensus' : 'map-marker');pin.style.background=color;const popup=new maplibregl.Popup({offset:14}).setDOMContent(el('div',title));new maplibregl.Marker({element:pin}).setLngLat([point.longitude,point.latitude]).setPopup(popup).addTo(map); }
function renderMap(items) {
  if(map){map.remove();map=null;} if(!items.length || !window.maplibregl){$('map-placeholder').hidden=false;return;}
  $('map-placeholder').hidden=true;
  try { const active=new maplibregl.Map({container:'map',style:mapStyles[$('map-style').value] || mapStyles.dark,center:[0,15],zoom:1.5,dragRotate:false});map=active;
    active.addControl(new maplibregl.NavigationControl({showCompass:false}),'top-right');
    active.addControl(new maplibregl.FullscreenControl(),'top-right');
    active.addControl(new maplibregl.ScaleControl({maxWidth:120,unit:'metric'}),'bottom-left');
    active.on('error',event=>{console.warn('Map resource unavailable',event.error);});
    active.on('load',()=>{if(map!==active)return;const bounds=new maplibregl.LngLatBounds(),points=[];
      items.forEach(item=>{const loc=item.location,index=current.ipLocations.findIndex(x=>x.ip===item.ip),color=colors[index%colors.length];
        if(loc.center && loc.radiusKm != null){const id='spread-'+index,polygon=circle(loc.center,loc.radiusKm);active.addSource(id,{type:'geojson',data:polygon});active.addLayer({id,type:'fill',source:id,paint:{'fill-color':color,'fill-opacity':.10}});active.addLayer({id:id+'-outline',type:'line',source:id,paint:{'line-color':color,'line-width':2}});polygon.geometry.coordinates[0].forEach(coord=>bounds.extend(coord));}
        loc.providers.forEach(p=>{points.push({type:'Feature',geometry:{type:'Point',coordinates:[p.longitude,p.latitude]},properties:{ip:item.ip,provider:p.name,area:area(p),color}});bounds.extend([p.longitude,p.latitude]);});
        if(loc.center && loc.agreement!=='low agreement')addMarker(loc.center,color,`${item.ip} · closest to source consensus: ${area(loc.center)}`,true);
      });
      active.addSource('provider-points',{type:'geojson',data:{type:'FeatureCollection',features:points},cluster:true,clusterRadius:44,clusterMaxZoom:11});
      active.addLayer({id:'provider-clusters',type:'circle',source:'provider-points',filter:['has','point_count'],paint:{'circle-color':'#1a5961','circle-radius':['step',['get','point_count'],20,8,25,18,31],'circle-stroke-color':'#a7fff0','circle-stroke-width':2}});
      active.addLayer({id:'provider-cluster-count',type:'symbol',source:'provider-points',filter:['has','point_count'],layout:{'text-field':['get','point_count_abbreviated'],'text-size':13},paint:{'text-color':'#ffffff'}});
      active.addLayer({id:'provider-points',type:'circle',source:'provider-points',filter:['!',['has','point_count']],paint:{'circle-color':['get','color'],'circle-radius':7,'circle-stroke-color':'#ffffff','circle-stroke-width':2}});
      active.on('click','provider-clusters',async event=>{const feature=active.queryRenderedFeatures(event.point,{layers:['provider-clusters']})[0];if(!feature)return;const zoom=await active.getSource('provider-points').getClusterExpansionZoom(feature.properties.cluster_id);active.easeTo({center:feature.geometry.coordinates,zoom});});
      active.on('click','provider-points',event=>{const feature=active.queryRenderedFeatures(event.point,{layers:['provider-points']})[0];if(!feature)return;const info=el('div');info.append(el('strong',feature.properties.ip),el('br'),el('span',`${feature.properties.provider}: ${feature.properties.area}`));new maplibregl.Popup({offset:12}).setLngLat(feature.geometry.coordinates).setDOMContent(info).addTo(active);});
      for(const layer of ['provider-clusters','provider-points'])active.on('mouseenter',layer,()=>active.getCanvas().style.cursor='pointer');
      for(const layer of ['provider-clusters','provider-points'])active.on('mouseleave',layer,()=>active.getCanvas().style.cursor='');
      if(!bounds.isEmpty())active.fitBounds(bounds,{padding:55,maxZoom:10,duration:0});
    });
  } catch(error){console.warn('Map failed',error);$('map-placeholder').hidden=false;}
}
window.addEventListener('maplibre-ready',()=>{if(current)renderLocations();});

function renderNetwork(){clear('network-content');const n=current.network;[['Selected IP',current.selectedIp],['Resolved DNS addresses',current.resolvedIps?.join(', ')],['Registry network',n?.rdap?.name || n?.rdap?.handle],['Registered range',n?.rdap?.startAddress && n?.rdap?.endAddress ? n.rdap.startAddress+' – '+n.rdap.endAddress : null],['Routed prefix',n?.routing?.prefix],['Origin ASN',n?.routing?.asns?.map(x=>'AS'+x).join(', ')]].forEach(([label,value])=>{const card=el('div',null,'network-item');card.append(el('span',label.toUpperCase()),el('strong',value || 'Unavailable'));$('network-content').append(card);});if(n?.rdap?.sourceUrl)$('network-content').append(link(n.rdap.sourceUrl,'Registry record ↗'));if(n?.routing?.sourceUrl)$('network-content').append(link(n.routing.sourceUrl,'RIPEstat record ↗'));}
function renderThreat(){clear('threat-content');const threat=current.threat;if(threat?.status==='ok'){const score=el('div',null,'threat-score');score.append(el('strong',threat.score == null ? '—' : threat.score+'/100'),el('p',`AbuseIPDB confidence score · ${threat.reports ?? 'unknown'} reports · last report ${time(threat.lastReportedAt)}`));$('threat-content').append(score,link(threat.sourceUrl,'About this source ↗'));}else $('threat-content').append(el('p',threat?.note || 'No live threat feed result is available. Import a STIX bundle for local matching.','muted'));}
function reconSection(parent,label,values,makeValue) {
  const section=el('div',null,'recon-section');section.append(el('h3',label));
  const list=el('div',null,'recon-list');
  if(!values?.length)list.append(el('span','None reported','muted'));
  else values.forEach(value=>list.append(makeValue ? makeValue(value) : el('span',value,'recon-chip')));
  section.append(list);parent.append(section);
}
function renderExposure() {
  const previous=$('exposure-ip').value, ips=[...new Set([current.selectedIp,...(current.resolvedIps || [])].filter(Boolean))];
  clear('exposure-ip');ips.forEach(ip=>{const option=el('option',ip);option.value=ip;$('exposure-ip').append(option);});
  $('exposure-ip').value=ips.includes(previous) ? previous : current.selectedIp || ips[0] || '';
  $('exposure-check').disabled=!ips.length;
  const ip=$('exposure-ip').value, record=current.exposures?.[ip];clear('exposure-content');
  if(!ip)return $('exposure-content').append(el('p','No public IP is available for an exposure lookup.','muted'));
  if(!record)return $('exposure-content').append(el('p','Check this IP for a passive InternetDB snapshot.','muted'));
  if(record.status!=='ok')return $('exposure-content').append(el('p',record.status==='no-record' ? 'InternetDB has no record for this IP.' : 'InternetDB is unavailable for this IP right now.','muted'));
  const metrics=el('div',null,'recon-metrics');for(const [label,value] of [['Ports',record.ports?.length || 0],['CVE leads',record.vulns?.length || 0],['Hostnames',record.hostnames?.length || 0]]){const metric=el('span',null,'recon-metric');metric.append(el('strong',value),el('span',label));metrics.append(metric);}$('exposure-content').append(metrics);
  const reviewPorts=new Set([21,22,23,3389,5900,6379,9200,27017]);
  reconSection($('exposure-content'),'Observed ports',record.ports,value=>el('span',value,'recon-chip'+(reviewPorts.has(value)?' lead':'')));
  reconSection($('exposure-content'),'Software hints',record.cpes);
  reconSection($('exposure-content'),'CVE associations to verify',record.vulns,value=>{const chip=el('span',null,'recon-chip lead');chip.append(link(`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(value)}`,value));return chip;});
  reconSection($('exposure-content'),'Observed hostnames',record.hostnames);
  if(record.tags?.length)reconSection($('exposure-content'),'Source tags',record.tags);
  $('exposure-content').append(link(record.sourceUrl,'InternetDB record ↗'));
}
$('exposure-ip').addEventListener('change',renderExposure);
$('exposure-check').addEventListener('click',async()=>{
  if(!current)return;
  const ip=$('exposure-ip').value;if(!ip)return;
  $('exposure-check').disabled=true;status('exposure-status',`Checking passive observations for ${ip}…`);
  try {const data=await api('/api/exposure?ip='+encodeURIComponent(ip));current.exposures={...current.exposures,[ip]:data.exposure};current.evidence=[...(current.evidence || []),...(data.evidence || [])];const saved=persistCurrentSnapshot();renderExposure();renderEvidence();status('exposure-status',`Passive snapshot updated for ${ip}.${saved ? ' Saved on this browser.' : ' Export to keep a copy.'}`);}
  catch(error){status('exposure-status',error.message,true);}finally{$('exposure-check').disabled=false;}
});
function renderDnsPosture() {
  clear('dns-posture-content');const dns=current.dnsPosture;
  $('dns-check').disabled=!current.input.domain;
  if(!current.input.domain)return $('dns-posture-content').append(el('p','Enter a domain to review its DNS records.','muted'));
  if(!dns)return $('dns-posture-content').append(el('p','Check this domain for public NS, MX, SPF, DMARC, and CAA records.','muted'));
  const checked=key=>dns.available?.[key] !== false;
  const entries=[['Nameservers',checked('ns') ? dns.ns?.join(', ') || 'None reported' : 'Unavailable'],['Mail servers',checked('mx') ? dns.mx?.join(', ') || 'None reported' : 'Unavailable'],['SPF',checked('spf') ? dns.spf?.length ? 'Record observed' : 'No SPF record observed' : 'Unavailable'],['DMARC',checked('dmarc') ? dns.dmarc?.length ? 'Record observed' : 'No DMARC record observed' : 'Unavailable'],['CAA',checked('caa') ? dns.caa?.length ? 'Record observed' : 'No CAA record observed' : 'Unavailable']];
  for(const [label,value] of entries){const row=el('div',null,'dns-posture-row');row.append(el('span',label),el('strong',value));$('dns-posture-content').append(row);}
  for(const [label,values] of [['SPF records',dns.spf],['DMARC records',dns.dmarc],['CAA records',dns.caa]])if(values?.length)reconSection($('dns-posture-content'),label,values);
}
$('dns-check').addEventListener('click',async()=>{
  const domain=current?.input?.domain;if(!domain)return;
  $('dns-check').disabled=true;status('dns-status',`Checking public DNS records for ${domain}…`);
  try {const data=await api('/api/dns-posture?domain='+encodeURIComponent(domain));current.dnsPosture=data.posture;current.evidence=[...(current.evidence || []),...(data.evidence || [])];const saved=persistCurrentSnapshot();renderDnsPosture();renderEvidence();status('dns-status',`DNS records updated.${saved ? ' Saved on this browser.' : ' Export to keep a copy.'}`);}
  catch(error){status('dns-status',error.message,true);}finally{$('dns-check').disabled=false;}
});
function renderWebPosture(){
  clear('web-posture-content');$('web-check').disabled=!!window.IP_INSIGHT_STATIC || !current.input.domain;
  if(window.IP_INSIGHT_STATIC){
    $('web-authorized').closest('label').hidden=true;
    return $('web-posture-content').append(el('p','The HTTPS header, certificate, and security.txt check runs in the localhost edition. GitHub Pages has no private server to perform this authorized check.','muted'));
  }
  if(!current.input.domain)return $('web-posture-content').append(el('p','Enter a domain to check its HTTPS response.','muted'));
  const web=current.webPosture;
  if(!web)return $('web-posture-content').append(el('p','Run the authorized check to view response headers, certificate details, and the disclosure contact.','muted'));
  const summary=el('p',`HTTPS ${web.homepage.status || 'unavailable'} · connected to ${web.connectedIp} · checked ${time(web.checkedAt)}`,'muted');$('web-posture-content').append(summary);
  for(const item of web.headerChecks || []){const line=el('div',null,'dns-posture-row');line.append(el('span',item.name),el('strong',item.status==='observed' ? 'Observed' : 'Review'));$('web-posture-content').append(line);}
  const cert=web.homepage.certificate;if(cert)reconSection($('web-posture-content'),'TLS certificate',[`Subject: ${cert.subject || 'Unknown'}`,`Issuer: ${cert.issuer || 'Unknown'}`,`Valid until: ${cert.validTo || 'Unknown'}`]);
  const disclosure=web.securityTxt;const p=el('p',disclosure.status===200 ? 'security.txt found' : `security.txt: HTTP ${disclosure.status || 'unavailable'}`,'muted');$('web-posture-content').append(p);
  if(disclosure.status===200){reconSection($('web-posture-content'),'Disclosure contacts',disclosure.contact || []);reconSection($('web-posture-content'),'Disclosure policies',disclosure.policy || []);$('web-posture-content').append(link(disclosure.url,'Open security.txt ↗'));}
  $('web-posture-content').append(el('p',web.note,'muted'));
}
$('web-check').addEventListener('click',async()=>{
  const domain=current?.input?.domain;if(!domain)return status('web-status','Investigate a domain first.',true);
  if(!$('web-authorized').checked)return status('web-status','Confirm authorization before making website requests.',true);
  $('web-check').disabled=true;status('web-status',`Checking ${domain} with two read-only HTTPS requests…`);
  try {const data=await post('/api/web-posture',{domain,authorized:true});current.webPosture=data.posture;current.evidence.push({name:`HTTPS posture (${domain})`,status:'ok',checkedAt:data.posture.checkedAt,url:data.posture.homepage.url});persistCurrentSnapshot();renderWebPosture();renderEvidence();status('web-status','HTTPS posture saved in this browser and included in reports.');}
  catch(error){status('web-status',error.message,true);}finally{$('web-check').disabled=false;}
});
function renderHosts(){
  const sub=current.subdomains,related=current.relatedHosts;
  text('subdomain-count',sub?.observedCount ?? 0);text('related-count',related?.observedCount ?? 0);
  if(!sub)hostTab='related';
  $('subdomains-tab').disabled=!sub;$('deep-subdomains').disabled=!current.input.domain;
  $('subdomains-tab').classList.toggle('active',hostTab==='subdomains');$('related-tab').classList.toggle('active',hostTab==='related');
  const data=hostTab==='subdomains' ? sub : related;
  text('hosts-description',data ? `${data.observedCount} observed names${data.truncated ? '; first '+data.items.length+' shown' : ''}. ${data.note}` : 'No host records available for this target.');
  const changes=current.assetChanges; $('subdomain-change').hidden=!changes || hostTab!=='subdomains';
  if(changes && hostTab==='subdomains')text('subdomain-change',`${changes.newNames.length} names not in your previous browser snapshot from ${time(changes.previousAt)}. Review scope before testing.`);
  clear('hosts-body');const filter=$('hostname-filter').value.trim().toLowerCase(),items=(data?.items || []).filter(x=>x.name.includes(filter));
  if(!items.length)return row($('hosts-body'),['No matching observed names','—','—','—']);
  const newNames=new Set(changes?.newNames || []);
  items.forEach(item=>{
    const tr=row($('hosts-body'),[item.name,item.observedIps?.join(', ') || 'Not verified','', '']);
    if(hostTab==='subdomains' && newNames.has(item.name))tr.firstChild.append(el('span','NEW','host-new'));
    (item.sources || []).forEach(source=>tr.children[2].append(el('span',source,'source-chip')));
    const check=item.dnsCheck;
    const label=!check || check.status==='not-checked' ? 'Not checked' : check.status==='resolves-a' ? `A: ${check.currentIps.join(', ')}` : check.status==='no-public-a' ? 'No public A answer' : 'Unavailable';
    tr.children[3].append(el('span',label,'dns-badge'+(check?.wildcardMatch || check?.status==='no-public-a'?' uncertain':check?.status==='resolves-a'?' positive':'')));
    if(check?.wildcardMatch)tr.children[3].append(el('small',' · matches wildcard DNS'));
    if(check?.aliases?.length)tr.children[3].append(el('small',' · CNAME '+check.aliases.join(', ')));
  });
}
$('subdomains-tab').addEventListener('click',()=>{hostTab='subdomains';if(current)renderHosts();});$('related-tab').addEventListener('click',()=>{hostTab='related';if(current)renderHosts();});$('hostname-filter').addEventListener('input',()=>{if(current)renderHosts();});
$('deep-subdomains').addEventListener('click',async()=>{
  const domain=current?.input?.domain;if(!domain)return status('deep-status','Investigate a domain first.',true);
  $('deep-subdomains').disabled=true;status('deep-status','Searching additional passive sources and checking public DNS for prioritized names…');
  try {const scan=await api('/api/subdomains?domain='+encodeURIComponent(domain));current.subdomains=scan.subdomains;current.subdomainScan={scannedAt:scan.scannedAt,checkedCount:scan.checkedCount,wildcardIps:scan.wildcardIps};current.evidence=[...(current.evidence || []),...(scan.evidence || [])];hostTab='subdomains';updateAssetChanges();const saved=persistCurrentSnapshot();renderHosts();renderEvidence();renderMatches();status('deep-status',`${scan.subdomains.observedCount} passive names found; ${scan.checkedCount} checked in DNS.${saved ? ' Saved on this browser.' : ' Export to keep a copy.'}`);}
  catch(error){status('deep-status',error.message,true);}finally{$('deep-subdomains').disabled=false;}
});
function renderEvidence(){clear('evidence-body');const evidence=current.evidence || [];text('source-summary',`${evidence.filter(x=>x.status==='ok').length}/${evidence.length} available`);evidence.forEach(item=>{const tr=row($('evidence-body'),[item.name,time(item.checkedAt),item.status==='ok' ? 'Available' : 'Unavailable'+(item.detail ? ' · '+item.detail : ''),'']);tr.lastChild.append(link(item.url,'Open ↗'));});}

$('stix-file').addEventListener('change',async e=>{const file=e.target.files?.[0];if(!file)return;if(file.size>5000000)return status('export-status','STIX file must be under 5 MB.',true);try{const data=JSON.parse(await file.text());if(data.type!=='bundle' || !Array.isArray(data.objects))throw new Error('Expected a STIX bundle with an objects array.');indicators=data.objects.filter(x=>x?.type==='indicator' && typeof x.pattern==='string').slice(0,10000);renderMatches();status('export-status',`Imported ${indicators.length} STIX indicators.`);}catch(error){status('export-status',error.message,true);}});
function matchingIndicators(){if(!current)return [];const names=new Set([current.selectedIp,current.input.domain,...(current.resolvedIps || []),...(current.subdomains?.items || []).map(x=>x.name),...(current.relatedHosts?.items || []).map(x=>x.name)].filter(Boolean).map(x=>x.toLowerCase()));return indicators.filter(x=>[...x.pattern.matchAll(/(?:ipv4-addr|ipv6-addr|domain-name):value\s*=\s*'([^']+)'/gi)].some(m=>names.has(m[1].toLowerCase())));}
function renderMatches(){clear('stix-matches');if(!indicators.length)return;const matches=matchingIndicators();$('stix-matches').append(el('p',`${matches.length} exact indicator matches in the imported bundle.`,'muted'));matches.slice(0,20).forEach(x=>{const item=el('div',null,'match-row');item.append(el('b',x.name || x.id || 'Indicator'));$('stix-matches').append(item);});}
$('save-notes').addEventListener('click',async()=>{
  if(!current)return status('export-status','Run or open an investigation first.',true);
  const notes=$('case-notes').value;
  const savedHere=current.localHistoryId ? localHistory.setNotes(current.localHistoryId,notes) : false;
  let savedCloud=false;
  try { if(current.historyId){await api('/api/history/'+current.historyId+'/notes',{method:'PATCH',headers:{'content-type':'application/json'},body:JSON.stringify({notes})});savedCloud=true;} }
  catch(error) { status('export-status',savedHere ? `Notes saved on this browser. Google history: ${error.message}` : error.message,true);return; }
  status('export-status',savedHere && savedCloud ? 'Notes saved here and to Google history.' : savedHere ? 'Notes saved on this browser.' : savedCloud ? 'Notes saved to Google history.' : 'Notes are included in exports; browser storage is unavailable.',!savedHere && !savedCloud);
});

const csv=rows=>rows.map(r=>r.map(v=>'"'+String(v ?? '').replaceAll('"','""')+'"').join(',')).join('\r\n')+'\r\n';
const escapeHtml=s=>String(s ?? '').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function report(){return {generatedAt:new Date().toISOString(),investigation:current,analystNotes:$('case-notes').value.trim(),matchedStixIndicators:matchingIndicators().map(x=>({id:x.id,name:x.name,pattern:x.pattern,confidence:x.confidence}))};}
function reportText(){
  const r=report(),d=r.investigation,exposure=Object.entries(d.exposures || {}),lines=['IP INSIGHT INVESTIGATION','Generated: '+r.generatedAt,'Target: '+(d.input.domain || d.selectedIp),'Selected IP: '+(d.selectedIp || 'unresolved'),'Current DNS IPs: '+(d.resolvedIps || []).join(', '),'','EXECUTIVE SUMMARY',`${d.subdomains?.observedCount || 0} passive subdomain names; ${exposure.reduce((n,[,x])=>n+(x.ports?.length || 0),0)} observed port leads; ${exposure.reduce((n,[,x])=>n+(x.vulns?.length || 0),0)} CVE associations to validate.`,'CVE associations and missing controls are not confirmed vulnerabilities. Verify scope, version, and impact.','','PUBLIC IP LOCATIONS'];
  (d.ipLocations || []).forEach(item=>{const loc=item.location;lines.push(`${item.ip}: ${area(loc?.center)} · agreement ${loc?.agreement || 'unknown'} · provider spread ${loc?.radiusKm == null ? 'unknown' : loc.radiusKm+' km'}`);(loc?.providers || []).forEach(p=>lines.push(`  ${p.name}: ${area(p)} (${p.latitude}, ${p.longitude}) ${p.sourceUrl}`));});
  lines.push('','NETWORK','Registry: '+(d.network?.rdap?.name || 'unavailable'),'Routed prefix: '+(d.network?.routing?.prefix || 'unavailable'),'ASN: '+((d.network?.routing?.asns || []).join(', ') || 'unavailable'));
  lines.push('','OBSERVED PORTS');
  if(!exposure.length)lines.push('No passive IP exposure snapshot was requested.');
  for(const [ip,record] of exposure)lines.push(`${ip}: ${(record.ports || []).join(', ') || 'none observed'} · source ${record.sourceUrl}`);
  lines.push('','CVE ASSOCIATIONS TO VALIDATE');
  if(!exposure.length)lines.push('No passive IP exposure snapshot was requested.');
  else if(exposure.every(([,record])=>!record.vulns?.length))lines.push('No CVE associations were reported in the retrieved snapshots.');
  for(const [ip,record] of exposure)for(const cve of record.vulns || [])lines.push(`${ip}: ${cve} · unverified passive association · ${record.sourceUrl}`);
  if(d.dnsPosture)lines.push('','DNS POSTURE','Nameservers: '+(d.dnsPosture.ns || []).join(', '),'Mail servers: '+(d.dnsPosture.mx || []).join(', '),'SPF: '+(d.dnsPosture.spf || []).join('; '),'DMARC: '+(d.dnsPosture.dmarc || []).join('; '),'CAA: '+(d.dnsPosture.caa || []).join('; '));
  if(d.webPosture){lines.push('','AUTHORIZED HTTPS POSTURE',`HTTPS status: ${d.webPosture.homepage.status}; connected IP: ${d.webPosture.connectedIp}`,...(d.webPosture.headerChecks || []).map(x=>`${x.name}: ${x.status}${x.value ? ' · '+x.value : ''}`),`Certificate subject: ${d.webPosture.homepage.certificate?.subject || 'unavailable'}`,`Certificate expires: ${d.webPosture.homepage.certificate?.validTo || 'unavailable'}`,`security.txt: HTTP ${d.webPosture.securityTxt.status || 'unavailable'}`,...(d.webPosture.securityTxt.contact || []).map(x=>`Disclosure contact: ${x}`));}
  lines.push('','OBSERVED SUBDOMAINS',...(d.subdomains?.items || []).map(x=>`${x.name} | passive sources: ${x.sources.join('; ')} | observed IPs: ${(x.observedIps || []).join(', ') || 'none'} | current DNS: ${x.dnsCheck?.status || 'not checked'} | current IPs: ${(x.dnsCheck?.currentIps || []).join(', ') || 'none'} | aliases: ${(x.dnsCheck?.aliases || []).join(', ') || 'none'}${x.dnsCheck?.wildcardMatch ? ' | wildcard match' : ''}`));
  if(d.assetChanges)lines.push('','NEW SINCE PRIOR BROWSER SNAPSHOT',...(d.assetChanges.newNames || []));
  lines.push('','IP NEIGHBORS',...(d.relatedHosts?.items || []).map(x=>x.name+' · '+x.observedIps.join('; ')),'','ANALYST NOTES',r.analystNotes || '(none)','','SOURCE LOG',...(d.evidence || []).map(x=>`${x.name} | ${x.status} | ${x.checkedAt} | ${x.url}`),'','LIMITS: Provider spread is not a statistical accuracy radius. IP locations cannot identify a person, device, or exact origin. Passive hostname records are incomplete and may be historical. IP neighbors can belong to unrelated organizations. Ports, CVE associations, and missing HTTP headers are review leads, not confirmed vulnerabilities.');
  return lines.join('\n');
}
function reportHtml(){
  const d=current, h=escapeHtml, exposure=Object.entries(d.exposures || {}), notes=$('case-notes').value.trim();
  const table=(columns,data)=>`<table><thead><tr>${columns.map(x=>`<th>${h(x)}</th>`).join('')}</tr></thead><tbody>${data.length ? data.map(row=>`<tr>${row.map(x=>`<td>${h(x ?? '')}</td>`).join('')}</tr>`).join('') : `<tr><td colspan="${columns.length}">No observations in this snapshot.</td></tr>`}</tbody></table>`;
  const section=(name,body)=>`<section><h2>${h(name)}</h2>${body}</section>`;
  const locations=(d.ipLocations || []).flatMap(item=>(item.location?.providers || []).map(p=>[item.ip,p.name,area(p),`${p.latitude}, ${p.longitude}`,item.location.radiusKm == null ? 'Unknown' : `${item.location.radiusKm} km`,p.sourceUrl]));
  const ports=exposure.flatMap(([ip,x])=>(x.ports || []).map(port=>[ip,port,x.status,x.sourceUrl]));
  const cves=exposure.flatMap(([ip,x])=>(x.vulns || []).map(cve=>[ip,cve,'Unverified association',x.sourceUrl]));
  const subdomains=(d.subdomains?.items || []).map(x=>[x.name,x.sources.join('; '),(x.observedIps || []).join('; '),x.dnsCheck?.status || 'Not checked',(x.dnsCheck?.currentIps || []).join('; '),x.dnsCheck?.wildcardMatch ? 'Yes' : 'No']);
  const dns=d.dnsPosture ? ['ns','mx','spf','dmarc','caa'].flatMap(key=>(d.dnsPosture[key] || []).map(value=>[key.toUpperCase(),value])) : [];
  const web=d.webPosture;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>IP Insight · ${h(d.input.domain || d.selectedIp)} report</title><style>
  :root{font:14px/1.5 Arial,sans-serif;color:#203042;background:#f3f6f8}*{box-sizing:border-box}body{max-width:1050px;margin:0 auto;padding:36px}header{background:#0e2133;color:#e9fbf7;padding:32px;border-radius:12px}header h1{font-size:30px;margin:0 0 8px}header p{margin:4px 0;color:#bad5d3}main{background:#fff;padding:30px;border-radius:12px;margin-top:18px}section{margin:0 0 32px;break-inside:avoid-page}h2{font-size:19px;border-bottom:2px solid #27ad9b;padding-bottom:7px;color:#123c4b}p{margin:8px 0}.lead{background:#e7f4f1;border-left:4px solid #21a88e;padding:13px}.warning{background:#fff5e6;border-left:4px solid #cc8f20;padding:13px}table{border-collapse:collapse;width:100%;font-size:12px;table-layout:fixed}th,td{border:1px solid #d5e1e7;text-align:left;vertical-align:top;padding:8px;overflow-wrap:anywhere}th{background:#e9f2f4}tr:nth-child(even){background:#f7fafb}.small{font-size:12px;color:#556b75;white-space:pre-wrap}@media print{body{padding:0;background:#fff}header,main{border-radius:0;margin:0}section{break-inside:auto}tr{break-inside:avoid}}
  </style></head><body><header><h1>IP Insight investigation</h1><p>Target: ${h(d.input.domain || d.selectedIp)}</p><p>Generated: ${h(new Date().toISOString())} · Selected IP: ${h(d.selectedIp || 'Unresolved')}</p></header><main>
  ${section('Executive summary',`<p class="lead">${h(d.resolvedIps?.length || 0)} current DNS IPs · ${h(d.subdomains?.observedCount || 0)} passive subdomain names · ${h(ports.length)} observed port leads · ${h(cves.length)} CVE associations to verify.</p><p class="warning">CVE associations and missing controls are leads, not confirmed vulnerabilities. Verify ownership, scope, service version, and impact before reporting.</p>`)}
  ${section('Target and method',`<p>Entered domain: ${h(d.input.domain || 'None')}<br>Requested IP: ${h(d.input.requestedIp || 'None')}<br>Current DNS answers: ${h((d.resolvedIps || []).join(', ') || 'None')}<br>Investigation time: ${h(d.completedAt)}</p><p class="small">Passive public sources were used for network, geolocation, hostnames, and IP exposure. The optional HTTPS posture check makes two read-only requests after authorization confirmation.</p>`)}
  ${section('Reported IP locations',table(['IP','Provider','Reported area','Coordinates','Provider spread','Source'],locations))}
  ${section('Observed ports',table(['IP','Port','Snapshot status','Source'],ports))}
  ${section('CVE associations to validate',table(['IP','CVE','Confidence','Source'],cves))}
  ${section('Domain DNS posture',table(['Record','Observed value'],dns))}
  ${section('Subdomain evidence',`<p class="small">Historical passive names may no longer resolve. Wildcard matches are flagged. The complete set is also in subdomains.csv.</p>${table(['Hostname','Sources','Observed IPs','DNS status','Current IPs','Wildcard match'],subdomains)}`)}
  ${section('Authorized HTTPS posture',web ? `<p>Connected to ${h(web.connectedIp)} · HTTPS ${h(web.homepage.status)} · certificate subject ${h(web.homepage.certificate?.subject || 'Unavailable')} · expires ${h(web.homepage.certificate?.validTo || 'Unavailable')}</p>${table(['Header/control','Assessment','Observed value'],(web.headerChecks || []).map(x=>[x.name,x.status,x.value]))}<p>security.txt: HTTP ${h(web.securityTxt.status || 'Unavailable')} · contacts ${h((web.securityTxt.contact || []).join('; ') || 'None observed')}</p>` : '<p>Not checked.</p>')}
  ${section('Related IP hostnames',table(['Hostname','Observed IPs','Sources'],(d.relatedHosts?.items || []).map(x=>[x.name,(x.observedIps || []).join('; '),(x.sources || []).join('; ')])))}
  ${section('Analyst notes',`<p class="small">${h(notes || 'No notes entered.')}</p>`)}
  ${section('Source log',table(['Source','Status','Checked at','Reference'],(d.evidence || []).map(x=>[x.name,x.status,x.checkedAt,x.url])))}
  ${section('Interpretation limits','<p class="small">IP map points are database estimates. Provider spread is not a statistical accuracy radius. Shared hosting and CDNs can place unrelated sites on the same IP. Passive records can be incomplete or stale. This report does not prove an exploitable vulnerability or identify a person or private address.</p>')}
  </main></body></html>`;
}
function rows(){
  const d=current,r=[['type','name','value','source']];r.push(['target',d.input.domain || d.selectedIp,d.selectedIp || '','DNS / input']);
  (d.ipLocations || []).forEach(item=>(item.location.providers || []).forEach(p=>r.push(['location',item.ip,`${p.name}; ${area(p)}; ${p.latitude}, ${p.longitude}`,p.sourceUrl])));
  (d.subdomains?.items || []).forEach(x=>r.push(['subdomain',x.name,`${x.observedIps.join('; ')}; current A ${(x.dnsCheck?.currentIps || []).join('; ')}; ${x.dnsCheck?.status || 'not checked'}`,x.sources.join('; ')]));
  (d.relatedHosts?.items || []).forEach(x=>r.push(['ip-neighbor',x.name,x.observedIps.join('; '),x.sources.join('; ')]));
  for(const [ip,record] of Object.entries(d.exposures || {})){for(const port of record.ports || [])r.push(['observed-port',ip,port,record.sourceUrl]);for(const cve of record.vulns || [])r.push(['cve-lead',ip,cve,record.sourceUrl]);}
  for(const [type,values] of Object.entries(d.dnsPosture || {}))if(Array.isArray(values))for(const value of values)r.push(['dns-'+type,d.input.domain,value,'Google DNS']);
  for(const item of d.webPosture?.headerChecks || [])r.push(['https-control',item.name,`${item.status}; ${item.value}`,d.webPosture.homepage.url]);
  (d.evidence || []).forEach(x=>r.push(['evidence',x.name,x.status,x.url]));r.push(['notes','Analyst notes',$('case-notes').value.trim(),'local']);return r;
}
function stixBundle(){const d=current,now=new Date().toISOString(),objects=[],refs=[];[...new Set([d.selectedIp,...(d.resolvedIps || [])].filter(Boolean))].forEach(ip=>{const type=ip.includes(':') ? 'ipv6-addr' : 'ipv4-addr',id=type+'--'+crypto.randomUUID();objects.push({type,spec_version:'2.1',id,value:ip});refs.push(id);});if(d.input.domain){const id='domain-name--'+crypto.randomUUID();objects.push({type:'domain-name',spec_version:'2.1',id,value:d.input.domain});refs.push(id);}const id='observed-data--'+crypto.randomUUID();objects.push({type:'observed-data',spec_version:'2.1',id,created:now,modified:now,first_observed:d.startedAt,last_observed:d.completedAt,number_observed:1,object_refs:refs});const notes=$('case-notes').value.trim();if(notes)objects.push({type:'note',spec_version:'2.1',id:'note--'+crypto.randomUUID(),created:now,modified:now,content:notes,object_refs:[id]});return {type:'bundle',id:'bundle--'+crypto.randomUUID(),objects};}
async function docxBlob(){
  const lib=window.docx;if(!lib?.Document || !lib?.Packer)throw new Error('DOCX library did not load.');
  const headings=new Set(['EXECUTIVE SUMMARY','PUBLIC IP LOCATIONS','NETWORK','OBSERVED PORTS','CVE ASSOCIATIONS TO VALIDATE','DNS POSTURE','AUTHORIZED HTTPS POSTURE','OBSERVED SUBDOMAINS','NEW SINCE PRIOR BROWSER SNAPSHOT','IP NEIGHBORS','ANALYST NOTES','SOURCE LOG']);
  const children=reportText().split('\n').map((line,index)=>new lib.Paragraph({text:line,heading:index===0 ? lib.HeadingLevel.TITLE : headings.has(line) ? lib.HeadingLevel.HEADING_1 : undefined,spacing:{before:headings.has(line) ? 240 : 0,after:line ? 80 : 140},keepNext:headings.has(line)}));
  const doc=new lib.Document({creator:'IP Insight',title:'IP Insight investigation report',sections:[{children}]});return lib.Packer.toBlob(doc);
}
async function exportZip(){
  if(!window.JSZip)throw new Error('ZIP library did not load.');
  const zip=new JSZip(),d=current;
  zip.file('report.json',JSON.stringify(report(),null,2));zip.file('report.csv',csv(rows()));zip.file('report.txt',reportText());zip.file('report.html',reportHtml());zip.file('report.docx',await docxBlob());zip.file('report.stix.json',JSON.stringify(stixBundle(),null,2));
  zip.file('locations.csv',csv([['ip','provider','city','region','country','latitude','longitude','source_url','checked_at','provider_spread_km'],...(d.ipLocations || []).flatMap(item=>(item.location.providers || []).map(p=>[item.ip,p.name,p.city,p.region,p.country,p.latitude,p.longitude,p.sourceUrl,p.checkedAt,item.location.radiusKm]))]));
  zip.file('subdomains.csv',csv([['hostname','observed_ips','sources','dns_status','current_ips','cname','wildcard_match'],...(d.subdomains?.items || []).map(x=>[x.name,x.observedIps.join('; '),x.sources.join('; '),x.dnsCheck?.status || 'not checked',(x.dnsCheck?.currentIps || []).join('; '),(x.dnsCheck?.aliases || []).join('; '),!!x.dnsCheck?.wildcardMatch])]));
  zip.file('new-subdomains.csv',csv([['hostname','previous_snapshot'],...(d.assetChanges?.newNames || []).map(name=>[name,d.assetChanges.previousAt])]));
  zip.file('ip-exposure.csv',csv([['ip','status','observed_ports','software_hints','cve_leads','hostnames','source'],...Object.entries(d.exposures || {}).map(([ip,record])=>[ip,record.status,(record.ports || []).join('; '),(record.cpes || []).join('; '),(record.vulns || []).join('; '),(record.hostnames || []).join('; '),record.sourceUrl])]));
  zip.file('observed-ports.csv',csv([['ip','port','source','interpretation'],...Object.entries(d.exposures || {}).flatMap(([ip,record])=>(record.ports || []).map(port=>[ip,port,record.sourceUrl,'Passive lead; verify service and scope']))]));
  zip.file('cve-leads.csv',csv([['ip','cve','source','interpretation'],...Object.entries(d.exposures || {}).flatMap(([ip,record])=>(record.vulns || []).map(cve=>[ip,cve,record.sourceUrl,'Unverified passive association']))]));
  zip.file('dns-posture.csv',csv([['record_type','value'],...Object.entries(d.dnsPosture || {}).flatMap(([type,values])=>Array.isArray(values) ? values.map(value=>[type,value]) : [])]));
  zip.file('web-posture.csv',csv([['domain','connected_ip','control','status','observed_value','checked_at'],...(d.webPosture?.headerChecks || []).map(x=>[d.webPosture.domain,d.webPosture.connectedIp,x.name,x.status,x.value,d.webPosture.checkedAt])]));
  zip.file('ip-neighbors.csv',csv([['hostname','observed_ips','sources'],...(d.relatedHosts?.items || []).map(x=>[x.name,x.observedIps.join('; '),x.sources.join('; ')])]));
  zip.file('source-log.csv',csv([['name','status','checked_at','url'],...(d.evidence || []).map(x=>[x.name,x.status,x.checkedAt,x.url])]));
  zip.file('README.txt','IP Insight case bundle. Open report.html for a formatted report and print it to PDF. report.docx is an editable document. report.json is the complete machine-readable snapshot. CSV files hold detailed subdomains, ports, CVE leads, DNS, HTTP posture, locations, neighbors, and the source log. Public IP locations are database estimates; provider spread is not an accuracy radius. Passive records can be incomplete or historical. CVE associations and missing headers are review leads, not confirmed vulnerabilities.\n');
  return zip.generateAsync({type:'blob',compression:'DEFLATE',compressionOptions:{level:6}});
}
document.querySelectorAll('[data-export]').forEach(b=>b.addEventListener('click',async()=>{if(!current)return status('export-status','Run an investigation first.',true);const kind=b.dataset.export,base=filename()+'-report';try{b.disabled=true;status('export-status','Preparing export…');if(kind==='zip')download(await exportZip(),base+'.zip');else if(kind==='json')download(new Blob([JSON.stringify(report(),null,2)],{type:'application/json'}),base+'.json');else if(kind==='csv')download(new Blob([csv(rows())],{type:'text/csv'}),base+'.csv');else if(kind==='docx')download(await docxBlob(),base+'.docx');else if(kind==='stix')download(new Blob([JSON.stringify(stixBundle(),null,2)],{type:'application/json'}),base+'.stix.json');else if(kind==='pdf'){window.print();return;}status('export-status',kind.toUpperCase()+' report downloaded.');}catch(error){status('export-status',error.message,true);}finally{b.disabled=false;}}));
$('batch-button').addEventListener('click',async()=>{const targets=[...new Set($('batch-input').value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean))];if(!targets.length || targets.length>5)return status('batch-status','Enter 1 to 5 domains or public IPs.',true);$('batch-button').disabled=true;clear('batch-body');$('batch-results').hidden=false;for(let i=0;i<targets.length;i++){status('batch-status',`Investigating ${i+1} of ${targets.length}…`);const target=targets[i];try{const isIp=!target.includes('://') && (target.includes(':') || /^\d+\.\d+\.\d+\.\d+$/.test(target));const d=await query(isIp ? '' : target,isIp ? target : '',true);row($('batch-body'),[target,d.selectedIp || '—',area(d.location?.center),d.location?.radiusKm == null ? 'Unknown' : d.location.radiusKm+' km']);}catch(error){row($('batch-body'),[target,'Failed',error.message,'—']);}}status('batch-status','Comparison complete.');$('batch-button').disabled=false;});
refreshAccount();

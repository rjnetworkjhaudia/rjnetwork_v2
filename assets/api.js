window.RJ_API = (() => {
  const DEFAULT = window.RJ_API_BASE || "";
  function base(){ return (localStorage.getItem("rj_api_base") || DEFAULT).replace(/\/$/,""); }
  async function request(path, options={}){
    const url = `${base()}${path}`;
    if(!base()) throw new Error("API_BASE_NOT_CONFIGURED");
    const res = await fetch(url,{...options,headers:{"content-type":"application/json",...(options.headers||{})}});
    let data={}; try{data=await res.json()}catch{}
    if(!res.ok){const e=new Error(data.error||`HTTP_${res.status}`);e.status=res.status;throw e}
    return data;
  }
  return {base,request};
})();

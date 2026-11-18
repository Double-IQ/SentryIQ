(function(){
    var welcome=document.getElementById('welcome');
    var reduced=window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    var displayTime=reduced?700:1500;
    var fadeTime=reduced?0:700;

    window.setTimeout(function(){
        if(!welcome)return;
        if(reduced){
            window.location.replace('index.php');
            return;
        }
        welcome.classList.add('fade-out');
        window.setTimeout(function(){
            window.location.replace('index.php');
        },fadeTime);
    },displayTime);
}());

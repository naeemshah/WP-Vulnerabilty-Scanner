<?php
  if(class_exists("WP_Vul_Scanner")) return;
  
class WP_Vul_Scanner
{
    private static $currentPluginName = "";

    public static function init()
    {
        add_action('admin_init', array('WP_Vul_Scanner', 'loadScripts'));
        add_action( 'wp_ajax_wp_vul_scan', array('WP_Vul_Scanner', 'scan') );

    }

    public function loadScripts()
    {

        wp_register_script('my-plugin-script', plugins_url('js/js.js', __FILE__));
        wp_enqueue_script('my-plugin-script');

    }

    public function scan()
    {

        
        
        $plugins = self::getAllPlugins();
        if (count($plugins) < 1) {
           self::sendJsonResponse(array("status"=>0,"msg"=>"No plugins Found"));
        }

        $pluginsData = array();

        unset($plugins['wp_vulnerability_scanner/wp_vulnerability_scanner.php']);
        foreach ($plugins as $key => $data) {
            $tmp        = explode("/", $key);
            $version    = $data['Version'];
            $pluginName = $tmp[0];
             self::$currentPluginName = $pluginName;
           $response = wp_remote_get('https://wpvulndb.com/api/v2/plugins/' . $pluginName);
            if (!isset($response["response"]["code"]) || $response["response"]["code"] != 200) {
               $pluginsData[self::$currentPluginName] = false;
            } else {

                $pluginsData[$pluginName] = self::processVul($version, json_decode($response['body'], true));
            }

        }
        self::sendJsonResponse(array("status"=>1,"data"=>$pluginsData));
        

    }

    public function getAllPlugins()
    {
        return get_plugins();
    }

    public function processVul($currentVersion, $data)
    {
        if (!$data) {
            return false;
        }

        if (!isset($data[self::$currentPluginName]["vulnerabilities"])) {
            return false;
        }

        $dataTosend = array();
        foreach ($data[self::$currentPluginName]["vulnerabilities"] as $key => $value) {
            
            if (!isset($value["fixed_in"])) {
                $dataTosend[] = self::prepareData($value,1);
            }else{
             $dataTosend[] = self::compareVersions($currentVersion,$value["fixed_in"],$value); 
            }
        }
        if(count($dataTosend) ==0 )
            return false;

        $dataTosend["is_vul"] = 0;
        $dataTosend["maybe_vul"]=0;
        foreach ($dataTosend as $key => $value) {
              if($value["type"] == 1)
                $dataTosend["is_vul"]++;
              elseif ($value["type"] == 2)
                $dataTosend["maybe_vul"]++;

        };


        return $dataTosend;


    }

    public function compareVersions($currentVersion, $fixVersion, $data)
    {
       if($currentVersion == $fixVersion)
        $dataTosend[self::$currentPluginName][] =  self::prepareData($data,1);
       else{
          $currentTmp = explode("-",$currentVersion);
          $fixedTmp  = explode("-",$fixVersion);
           foreach ($currentTmp as $key => $value) {
                if(!isset($fixedTmp[$key]) || isset($fixedTmp[$key]) && $value < $fixedTmp[$key]){
                  return self::prepareData($data,2);
                   
                }

           }
                }

                return self::prepareData($data,0);
    }

    public function prepareData($data,$type)
    {
        return array(
            "title"     => $data["title"],
            "vuln_type" => $data["vuln_type"],
            "type"=>$type
        );
    }

    public function sendJsonResponse($data){
        header('Content-Type: application/json');
          echo json_encode($data);
          die;
    }

}

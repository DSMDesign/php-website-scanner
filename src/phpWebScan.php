<?php
/**
 *  Class to Scan Websites for Malware, Updates, Added or Removed Files
 */

class phpWebScan {
    private $infected_files = array();
    private $scanned_files  = array();
    private $fileindex      = array();
    private $modified       = array();
    private $oldfileindex;
    private $lastscan;

    /**
     * Function to scan a directory for files or more directories
     * @string $dir The directory to scan
     */
    public function scan($dir) {
        // If having issues with timing out uncomment this line
        // set_time_limit(60);

        $this->scanned_files[] = $dir;

        $files = scandir($dir);

        // loop through the DIR and check for files or Directories
        foreach($files as $file) {
            if(is_file($dir.'/'.$file) && !in_array($dir.'/'.$file,$this->scanned_files)) {
                // grab the cile contents and check for malware injection
                $this->check(file_get_contents($dir.'/'.$file),$dir.'/'.$file);
            } elseif(is_dir($dir.'/'.$file) && substr($file,0,1) != '.') {
                // do not scan scanner log files as they change every scan
                if($file != 'scanner-logs')
                    $this->scan($dir.'/'.$file);
            }
        }
    }

    /**
     * Function to check the file contents for injections
     * @string $contents Content of the file
     * @string $file     Filename being checked
     */
    public function check($contents,$file) {
        $this->scanned_files[] = $file;
        $this->fileindex[]     = $file;

        // check for injection
        if(preg_match('/eval\((base64|eval|\$_|\$\$|\$[A-Za-z_0-9\{]*(\(|\{|\[))/i',$contents)) {
            $this->infected_files[] = $file;
            echo 'Infected File : '.$file.'<br/>';
        }

        /* if you are looking for other injected code add here */
        if(preg_match('/x65\/li\x6eweb/' , $contents)){
            $this->infected_files[] = $file;
            echo 'Infected File : '.$file.'<br/>';
        }

        // check for modification
        if(filemtime($file) > $this->lastscan){
            $this->modified[] = $file.' modified '.date ("F d Y H:i:s.", filemtime($file));
        }
    }

    /**
     * Function to create a message containing results of scan
     */
    public function sendalert() {
        // files count
        $message = "== FILES SCANNED == <br/><br/>";
        $message .= count($this->fileindex)." files scanned <br/>";
        $message .= count($this->oldfileindex)." last scanned <br/><br/>";

        // infected file list
        if(count($this->infected_files) != 0) {
            $message .= "== MALICIOUS CODE FOUND == <br/><br/>";
            $message .= "The following files appear to be infected: <br/>";
            foreach($this->infected_files as $inf) {
                $message .= "  -  $inf <br/>";
            }
        } else {
            $message .= "<br/>== LOOKS ALL CLEAN TO ME == <br/><br/>";
        }

        // files added
        $difference = array_diff($this->fileindex, $this->oldfileindex);
        if(count($difference) > 0){
            // set flag for file write
            $updateList = true;

            $message .= "<br/>== FILES ADDED == <br/><br/>";
            foreach ($difference as $added) {
                $message .= $added."<br/>";
            }
        } else {
            $message .= "<br/>== NO FILES HAVE BEEN ADDED == <br/><br/>";
        }

        // files Removed
        $removed = array_diff($this->oldfileindex, $this->fileindex);
        if(count($removed) > 0){
            // set flag for file write
            $updateList = true;

            // add results to message
            $message .= "<br/>== FILES REMOVED == <br/><br/>";
            foreach ($removed as $deleted) {
                $message .= $deleted."<br/>";
            }
        } else {
            $message .= "<br/>== NO FILES HAVE BEEN REMOVED == <br/><br/>";
        }

        // files modified
        if(count($this->modified) > 0) {
            // set flag for file write
            $updateList = true;

            $message .= "<br/>== FILES MODIFIED == <br/><br/>";
            foreach ($this->modified as $modded) {
                $message .= $modded."<br/>";
            }
        } else {
            $message .= "<br/>== NO FILES HAVE BEEN MODIFIED == <br/><br/>";
        }

        // do we need to create an updated file list
        if($updateList){
            // create an update file list
            self::writeFile();
        }

        $header = "<h2>PHP Web Scanner Results</h2><hr/><br/>";
        $footer .= "<br/><br/><br/>Website was scanned by PHP Web Scanner by <a href=\"https://www.southcoastweb.co.uk\" target=\"_blank\">South Coast Web Design Ltd</a>";

        $headers = "MIME-Version: 1.0" . "\r\n";
        $headers .= "Content-type:text/html;charset=UTF-8" . "\r\n";
        // More headers
        $headers .= 'From: PHP Website Scanner <'.FROM_EMAIL.'>' . "\r\n";

        mail(EMAIL_ALERT, 'Website Scan results', $header.$message.$footer, $headers);

        echo '<pre>'.$message.'</pre>';

        // log record
        self::logResults($message);
    }

    /**
     * Function will create a file containing a serialiazed array of files scanned
     */
    public function writeFile() {
        // debug. Uncomment to get a fresh file list
        // $this->freshclean();

        $data = serialize($this->fileindex);
        $fopen = fopen('scanner-logs/scannerfiles.txt', 'w+');
        fwrite($fopen, $data);
        fclose($fopen);
    }

    /**
     * Function to read the previously canned filenames and unserialize them to an array
     * It will also return the last time a file list was created
     */
    public function readFile() {
        $this->oldfileindex = unserialize(file_get_contents('scanner-logs/scannerfiles.txt'));
        $this->lastscan = filemtime('scanner-logs/scannerfiles.txt');
    }

    /**
     * Function to help with debugging. Will clear the fileindex array.
     */
    public function freshclean() {
        unset($this->fileindex);
        $this->fileindex[] = '';
    }

    /**
     * Function to log results for future reading
     * @string $message Records a log of the results
     */
    public function logResults($message) {
        $fopen = fopen('scanner-logs/scan-results-'.date('H:i').'.log', 'w+');
        fwrite($fopen, $message);
        fclose($fopen);
    }
}




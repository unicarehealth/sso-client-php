<?php
	namespace Csa\Sso\Client;

	use Exception;
	
	// AES packetization class.  Requires phpseclib AES.php + Rijndael.php
	// (C) 2017 CubicleSoft.  All Rights Reserved.
	//
	// Class renamed for SSO Client support.

	class ExtendedAES
	{
		// Uses AES to create an encapsulated data packet.  Does not support streams.
		static function CreateDataPacket($data, $key, $options = array())
		{
			$data = (string)$data;
			if (!isset($options["prefix"]))  $options["prefix"] = uniqid(mt_rand(), true);
			$options["prefix"] = strtolower(dechex(crc32($options["prefix"])));
			if (!isset($options["lightweight"]) || !$options["lightweight"])  $data = $options["prefix"] . "\n" . strtolower(sha1($data)) . "\n" . $data . "\n";
			else  $data = $options["prefix"] . "\n" . strtolower(dechex(crc32($data))) . "\n" . $data . "\n";

			self::CheckDependencies();

			if (!isset($options["mode"]))  $options["mode"] = "ECB";
			if (!isset($options["iv"]))  $options["iv"] = str_repeat("\x00", 16);

			$aes = new \phpseclib\Crypt\AES($options["mode"] == "CBC" ? \phpseclib\Crypt\AES::MODE_CBC : \phpseclib\Crypt\AES::MODE_ECB);
			$aes->setKey($key);
			if (isset($options["iv"]))  $aes->setIV($options["iv"]);
			$aes->disablePadding();
			if (strlen($data) % 16 != 0)  $data = str_pad($data, strlen($data) + (16 - (strlen($data) % 16)), "\x00");
			$data = $aes->encrypt($data);

			if (isset($options["key2"]))
			{
				$data = substr($data, -1) . substr($data, 0, -1);

				if (isset($options["iv2"]))  $options["iv"] = $options["iv2"];
				else  unset($options["iv"]);

				if ($options["mode"] != "ECB" && (!isset($options["iv"]) || $options["iv"] == ""))  return false;

				$aes->setKey($options["key2"]);
				if (isset($options["iv"]))  $aes->setIV($options["iv"]);
				$data = $aes->encrypt($data);
			}

			return $data;
		}

		// Checks required classes are available.
		static function CheckDependencies()
		{
			if (!class_exists("\\phpseclib\\Crypt\\AES"))
			{					
				throw new Exception("phpseclib not found (AES)");
			}
			
			// $directory = dirname(__FILE__);
			// do
			// {
				// $directory = dirname($directory);
				// if (file_exists($directory . '/composer.json'))
				// {
					// require_once str_replace("\\", "/", $directory) . "/vendor/autoload.php";
					// break;
				// }
			// } while($directory != '/');
			
			// if (!class_exists("\\phpseclib\\Crypt\\AES"))
			// {
				//error_log("phpseclib not found (AES)");
				//exit();
			//}					
		}
		
		// Uses AES to extract the data from an encapsulated data packet and validates the data.  Does not support streams.
		static function ExtractDataPacket($data, $key, $options = array())
		{
			$data = (string)$data;

			if (!isset($options["mode"]))  $options["mode"] = "ECB";
			if ($options["mode"] != "ECB" && (!isset($options["iv"]) || $options["iv"] == ""))  return false;

			self::CheckDependencies();

			if (isset($options["key2"]))
			{
				$options2 = $options;
				if (isset($options["iv2"]))  $options["iv"] = $options["iv2"];
				else  unset($options["iv"]);

				$aes = new \phpseclib\Crypt\AES($options["mode"] == "CBC" ? \phpseclib\Crypt\AES::MODE_CBC : \phpseclib\Crypt\AES::MODE_ECB);
				$aes->setKey($options["key2"]);
				if (isset($options["iv"]))  $aes->setIV($options["iv"]);
				$aes->disablePadding();
				$data = $aes->decrypt($data);

				$data = substr($data, 1) . substr($data, 0, 1);
				$options = $options2;
			}

			$aes = new \phpseclib\Crypt\AES($options["mode"] == "CBC" ? \phpseclib\Crypt\AES::MODE_CBC : \phpseclib\Crypt\AES::MODE_ECB);
			$aes->setKey($key);
			if (isset($options["iv"]))  $aes->setIV($options["iv"]);
			$aes->disablePadding();
			$data = $aes->decrypt($data);

			if ($data === false)  return false;

			$pos = strpos($data, "\n");
			if ($pos === false)  return false;
			$data = substr($data, $pos + 1);

			$pos = strpos($data, "\n");
			if ($pos === false)  return false;
			$check = substr($data, 0, $pos);
			$data = substr($data, $pos + 1);

			$pos = strrpos($data, "\n");
			if ($pos === false)  return false;
			$data = substr($data, 0, $pos);

			if (!isset($options["lightweight"]) || !$options["lightweight"])
			{
				if ($check !== strtolower(sha1($data)))  return false;
			}
			else if ($check !== strtolower(dechex(crc32($data))))  return false;

			return $data;
		}
	}
?>
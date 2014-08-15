<?php

/*
	ECSRP
	Copyright (C) 2014  Steve "Sc00bz" Thomas (steve at tobtu dot com)

	This program is free software; you can redistribute it and/or
	modify it under the terms of the GNU General Public License
	as published by the Free Software Foundation; either version 2
	of the License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

/**
 * HKDF - HMAC-based key derivation function.
 *
 * @param string      $inputKeyingMaterial
 * @param int         $keySize - Key size in bytes
 * @param string      $info    - Default is ''
 * @param string|null $salt    - Default is null
 * @param string      $algo    - Default is 'sha256'
 * @return string|null - On success string, otherwise null
 */
function hkdf($inputKeyingMaterial, $keySize, $info = '', $salt = null, $algo = 'sha256')
{
	$hmacSize = strlen(hash_hmac($algo, '', '')) / 2;
	if ($keySize > $hmacSize * 255)
	{
		return null;
	}
	if (!isset($salt))
	{
		$salt = str_repeat("\0", $hmacSize);
	}
	$extractedKey = hash_hmac($algo, $salt, $inputKeyingMaterial, true);
	$keyLen = 0;
	$key = str_repeat("\0", $hmacSize);
	for ($i = 1; $keyLen < $keySize; $i++)
	{
		$key .= hash_hmac($algo, substr($key, -$hmacSize) . $info . chr($i), $extractedKey, true);
		$keyLen += $hmacSize;
	}
	return substr($key, $hmacSize, $keySize);
}

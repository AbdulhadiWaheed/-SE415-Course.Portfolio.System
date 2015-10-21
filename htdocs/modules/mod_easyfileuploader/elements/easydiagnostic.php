<?php
/**
* @version		2.5
* @author		Michael A. Gilkes (jaido7@yahoo.com)
* @copyright	Michael Albert Gilkes
* @license		GNU/GPLv2
*/

/*

Easy File Uploader Module for Joomla!
Copyright (C) 2010-2013  Michael Albert Gilkes

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

// no direct access
defined('JPATH_BASE') or die();

if(!class_exists('JPseudoElementBase'))
{
	if(version_compare(JVERSION,'1.6.0','ge'))
	{
		//get joomla form related functions
		jimport('joomla.form.formfield');
		
		class JPseudoElementBase extends JFormField
		{
			// This line is required to keep Joomla! 1.6/1.7 from complaining
			public function getInput() {}
		}               
	}
	else
	{
		class JPseudoElementBase extends JElement {}
	}
}

class JPseudoEasyDiagnostic extends JPseudoElementBase
{
	//specify the custom field type
	protected $type = 'easydiagnostic';
	
	//setup the custom field's details
	function getInput()
	{
		return ' ';
	}
	
	function getLabel()
	{
		$html = '<p style="color:black;">PHP Version: '.PHP_VERSION.'.</p>';
		if (defined('FILEINFO_MIME_TYPE'))
		{	
			$html.= '<p style="color:green;">FILEINFO_MIME_TYPE is defined.</p>';
			if (function_exists('finfo_open'))
			{
				if (is_callable('finfo_open'))
				{
					$html.= '<p style="color:green;">finfo_open is callable.</p>';
				}
				else
				{
					$html.= '<p style="color:blue;">finfo_open is NOT callable.</p>';
				}
			}
			else
			{
				$html.= '<p style="color:red;">finfo_open doesn\'t exist.</p>';
			}
			
			if (function_exists('finfo_file'))
			{
				if (is_callable('finfo_file'))
				{
					$html.= '<p style="color:green;">finfo_file is callable.</p>';
				}
				else
				{
					$html.= '<p style="color:blue;">finfo_file is NOT callable.</p>';
				}
			}
			else
			{
				$html.= '<p style="color:red;">finfo_file doesn\'t exist.</p>';
			}
			if (function_exists('finfo_close'))
			{
				if (is_callable('finfo_close'))
				{
					$html.= '<p style="color:green;">finfo_close is callable.</p>';
				}
				else
				{
					$html.= '<p style="color:blue;">finfo_close is NOT callable.</p>';
				}
			}
			else
			{
				$html.= '<p style="color:red;">finfo_close doesn\'t exist.</p>';
			}
		}
		else
		{
			$html.= '<p style="color:red;">FILEINFO_MIME_TYPE is NOT defined.</p>';
		}
		
		if (function_exists('mime_content_type'))
		{
			if (is_callable('mime_content_type'))
			{
				$html.= '<p style="color:green;">mime_content_type is callable.</p>';
			}
			else
			{
				$html.= '<p style="color:blue;">mime_content_type is NOT callable.</p>';
			}
		}
		else
		{
			$html.= '<p style="color:red;">mime_content_type doesn\'t exist.</p>';
		}
		
		if (strtoupper(substr(PHP_OS,0,3)) !== 'WIN')
		{
			$html.= '<p style="color:black;">This is a NON-Windows OS: '.PHP_OS.'.</p>';
			if (function_exists('escapeshellarg'))
			{
				if (is_callable('escapeshellarg'))
				{
					$html.= '<p style="color:green;">escapeshellarg is callable.</p>';
				}
				else
				{
					$html.= '<p style="color:blue;">escapeshellarg is NOT callable.</p>';
				}
			}
			else
			{
				$html.= '<p style="color:red;">escapeshellarg doesn\'t exist.</p>';
			}
			
			if (function_exists('exec'))
			{
				if (is_callable('exec'))
				{
					$html.= '<p style="color:green;">exec is callable.</p>';
				}
				else
				{
					$html.= '<p style="color:blue;">exec is NOT callable.</p>';
				}
			}
			else
			{
				$html.= '<p style="color:red;">exec doesn\'t exist.</p>';
			}
			
			if (function_exists('shell_exec'))
			{
				if (is_callable('shell_exec'))
				{
					$html.= '<p style="color:green;">shell_exec is callable.</p>';
				}
				else
				{
					$html.= '<p style="color:blue;">shell_exec is NOT callable.</p>';
				}
			}
			else
			{
				$html.= '<p style="color:red;">shell_exec doesn\'t exist.</p>';
			}
		}
		else
		{
			$html.= '<p style="color:red;">This is Windows OS: '.PHP_OS.'.</p>';
		}
		
		$support = '<hr /><p>Please feel free to create your own buttons for this plugin at my button maker site: <a href="http://www.demos.michaelgilkes.com/buttonmaker/" target="_blank">http://www.demos.michaelgilkes.com/buttonmaker/</a></p>';
		$support.= '<p>Please visit the support sites for help:</p>';
		$support.= '<ul><li><a href="http://support.michaelgilkes.com/" target="_blank">Support Forum</a></li>';
		$support.= '<li><a href="https://www.valorapps.com/faq.html" target="_blank">Official FAQ</a></li>';
		$support.= '<li><a href="https://www.valorapps.com/product-docs.html" target="_blank">Official Documentation</a></li></ul>';
		
		return '<hr style="clear:both;" />'.$html.$support.'<hr />';
	}
	
	function getTitle()
	{
		return $this->getLabel();
	}
	
	/* JElement Stuff */
	function fetchTooltip($label, $description, &$node, $control_name, $name)
	{
		return '&nbsp;';
	}

	function fetchElement($name, $value, &$node, $control_name)
	{
		return $this->getLabel();
	}
}



if (version_compare(JVERSION,'1.6.0','ge'))
{
	class JFormFieldEasyDiagnostic extends JPseudoEasyDiagnostic {}
}
else
{
	class JElementEasyDiagnostic extends JPseudoEasyDiagnostic {}                
}

<?php
/**
* @version		2.0
* @author		Michael A. Gilkes (jaido7@yahoo.com)
* @copyright	Michael Albert Gilkes
* @license		GNU/GPLv2
*/

//no direct access
defined( '_JEXEC' ) or die( 'Restricted access' );

//get the module class designation
$moduleclass_sfx = htmlspecialchars($params->get('moduleclass_sfx'));

//set up the custom text
$labelText = $params->get('efu_label');
$buttonText = $params->get('efu_button');
$questionText = $params->get('efu_question');
$yesText = $params->get('efu_yes');
$noText = $params->get('efu_no');
if ($params->get('efu_custom') == 0)
{
	$labelText = JText::_('MOD_EFU_LABEL_TEXT');
	$buttonText = JText::_('MOD_EFU_BUTTON_TEXT');
	$questionText = JText::_('MOD_EFU_QUESTION_TEXT');
	$yesText = JText::_('JYES');
	$noText = JText::_('JNO');
}

//specify the action
$action = JURI::current();

?>
<div class="<?php echo $moduleclass_sfx;?>">
	<!-- Input form for the File Upload -->
	<form enctype="multipart/form-data" action="<?php echo $action; ?>" method="post">
		<?php if ($params->get('efu_multiple') == "1"): ?>
		<label for=<?php echo '"'.$params->get('efu_variable').'[]"'; ?>><?php echo $labelText; ?></label>
		<?php else: ?>
		<?php echo $labelText; ?><br />
		<?php endif; ?>
		<?php 
		$max = intval($params->get('efu_multiple'));
		for ($i = 0; $i < $max; $i++): ?>
		<input type="file" name=<?php echo '"'.$params->get('efu_variable').'[]"'; ?> id=<?php echo '"'.$params->get('efu_variable').'[]"'; ?> style="margin-top:1px; margin-bottom:1px;" /> 
		<br />
		<?php endfor; ?>
		<?php if ($params->get('efu_replace') == true): /* 1 means 'Yes' or true. 0 means 'No' or false. */ ?>
		<div><?php echo $questionText; ?></div>
		<input type="radio" name="answer" value="1" /><?php echo $yesText; ?><br />
		<input type="radio" name="answer" value="0" checked /><?php echo $noText; ?><br />
		<br />
		<?php endif; ?>
		<input type="submit" name="submit" value=<?php echo '"'.$buttonText.'"'; ?> />
	</form>
	<!-- Display the Results of the file upload if uploading was attempted -->
	<?php if (isset($_FILES[$params->get('efu_variable')])) : ?>
	<div style="display:inline-block; position:relative; margin:1em; padding:1em; width:auto; background:<?php echo $params->get('efu_results_bgcolor'); ?>; border: 1px solid grey;">
		<?php echo $result; ?>
	</div>
	<?php endif; ?>
</div>
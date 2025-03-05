<?php
function GetRateFromCBR($CURRENCY) 
{
    global $DB;
    global $APPLICATION;

    if (!preg_match('/^[A-Z]{3}$/', $CURRENCY)) {
        // Invalid currency code format
        return false;
    }

    CModule::IncludeModule('currency');
    if (!CCurrency::GetByID($CURRENCY)) {
        // Такой валюты нет на сайте, агент в этом случае удаляется
        return false;
    }
    
    $DATE_RATE = date("d.m.Y"); // Сегодня
    $QUERY_STR = "date_req=" . $DB->FormatDate($DATE_RATE, CLang::GetDateFormat("SHORT", $lang), "D.M.Y");

    // Делаем запрос к www.cbr.ru с просьбой отдать курс на нынешнюю дату
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "http://www.cbr.ru/scripts/XML_daily.asp?" . $QUERY_STR);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    $strQueryText = curl_exec($ch);
    curl_close($ch);

    if ($strQueryText === false) {
        // Ошибка запроса
        return false;
    }

    // Получаем XML и конвертируем в кодировку сайта
    $charset = "windows-1251";
    if (preg_match('/<\?XML[^>]+encoding=["\']([^"\']+)["\'][^>]*\?>/i', $strQueryText, $matches)) {
        $charset = trim($matches[1]);
    }
    $strQueryText = preg_replace("/<!DOCTYPE[^>]*>/", "", $strQueryText);
    $strQueryText = preg_replace("/<\?XML[^>]*\?>/", "", $strQueryText);
    $strQueryText = $APPLICATION->ConvertCharset($strQueryText, $charset, SITE_CHARSET);

    require_once($_SERVER["DOCUMENT_ROOT"] . "/bitrix/modules/main/classes/general/xml.php");

    // Парсим XML
    $objXML = new CDataXML();
    $res = $objXML->LoadString($strQueryText);
    if ($res !== false) {
        $arData = $objXML->GetArray();
    } else {
        $arData = false;
    }

    $NEW_RATE = array();

    // Получаем курс нужной валюты $CURRENCY
    if (is_array($arData) && isset($arData["ValCurs"]["#"]["Valute"])) {
        foreach ($arData["ValCurs"]["#"]["Valute"] as $valute) {
            if ($valute["#"]["CharCode"][0]["#"] === $CURRENCY) {
                $NEW_RATE['CURRENCY'] = $CURRENCY;
                $NEW_RATE['RATE_CNT'] = intval($valute["#"]["Nominal"][0]["#"]);
                $NEW_RATE['RATE'] = doubleval(str_replace(",", ".", $valute["#"]["Value"][0]["#"]));
                $NEW_RATE['DATE_RATE'] = $DATE_RATE;
                break;
            }
        }
    }

    if (isset($NEW_RATE['RATE']) && isset($NEW_RATE['RATE_CNT'])) {
        // Курс получили, возможно, курс на нынешнюю дату уже есть на сайте, проверяем
        CModule::IncludeModule('currency');
        $arFilter = array(
            "CURRENCY" => $NEW_RATE['CURRENCY'],
            "DATE_RATE" => $NEW_RATE['DATE_RATE']
        );
        $by = "date";
        $order = "desc";

        $db_rate = CCurrencyRates::GetList($by, $order, $arFilter);
        if (!$ar_rate = $db_rate->Fetch()) {
            // Такого курса нет, создаём курс на нынешнюю дату
            CCurrencyRates::Add($NEW_RATE);
        }
    }

    // Возвращаем код вызова функции, чтобы агент не "убился"
    return 'GetRateFromCBR("' . $CURRENCY . '");';
}
?>
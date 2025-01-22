package com.mwdle.autovt;

import com.codeborne.selenide.Condition;
import com.codeborne.selenide.Configuration;
import com.codeborne.selenide.Selenide;
import com.codeborne.selenide.SelenideElement;
import org.openqa.selenium.By;

import java.awt.*;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.codeborne.selenide.Condition.*;
import static com.codeborne.selenide.Selectors.shadowCss;
import static com.codeborne.selenide.Selenide.*;

public class AutoVT {

    // TODO: Setup checks for community scores for uploads.
    // TODO: Don't allow uploading files larger than limit, and implement corresponding behavior for reports.
    // TODO: Move selectors into page object file.

    public static final Duration REPORT_TIMEOUT = Duration.ofMinutes(3); // The maximum amount of time to wait for the file to upload, for the file to get scanned, and the report to load.
    public static final Duration CAPTCHA_TIMEOUT = Duration.ofMinutes(20);

    public static final File currentDir = new File(System.getProperty("user.dir"));
    public static final File reportsDir = new File(currentDir, "reports");
    public static final File screenshotsDir = new File(currentDir, "reports/screenshots");
    private static String detectionsReportFilepath;
    private static String cleanReportFilepath;

    public static void openVT() {
        open("https://www.virustotal.com/");
    }

    public static void login(String username, String password) {
        if (!username.isEmpty() && !password.isEmpty()) { // Only login if username and password are provided
            SelenideElement signInNavButton = $(shadowCss("div > a.signin", "body > vt-ui-shell", "uno-navbar", "div > div.hstack > uno-account-widget")).should(exist);
            checkForCaptcha();
            signInNavButton.click();
            $(By.id("userId")).shouldBe(interactable).setValue(username);
            $(By.id("password")).shouldBe(interactable).setValue(password);
            $x("//input[contains(@type, 'checkbox')]").shouldBe(interactable).setSelected(true);
            $(By.id("sign-in-btn")).shouldBe(interactable).click();
            Selenide.sleep(1500); // Wait for the page to load to determine if multi-factor authentication is required
            SelenideElement multiFactorAuth = $x("//*[contains(text(), 'Authentication code')]");
            if (multiFactorAuth.isDisplayed()) {
                Toolkit.getDefaultToolkit().beep(); // Make a sound to notify the user that multi-factor authentication is required
                $(By.id("code2fa")).shouldHave(Condition.attributeMatching("value", "^[0-9]{6}$"), Duration.ofMinutes(5)); // Wait for up to 5 minutes for the user to enter the authentication code
                $(By.id("sign-in-btn")).shouldBe(interactable).click();
            }
        }
    }

    public static void appendResultToReport(File file, String numberOfDetections) {
        String screenshotName = file.getName().replace(' ', '_') + "_VT_screenshot";
        Selenide.screenshot(screenshotName);
        File screenshot = new File(screenshotsDir, screenshotName + ".png");
        boolean isClean = numberOfDetections.equals("No");
        try (FileWriter reportFileWriter = new FileWriter(isClean ? cleanReportFilepath : detectionsReportFilepath, true)) {
            reportFileWriter.append(generateUploadResultReport(file.getName(), file.getAbsolutePath(), numberOfDetections.toLowerCase(), Selenide.webdriver().driver().url(), screenshot.getAbsolutePath()));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void collectResultsForReport(File file) {
        SelenideElement reportSummary = $(shadowCss("div > div.card-header > div.fw-bold", "#view-container > file-view", "#report > vt-ui-file-card")).should(exist, Duration.ofSeconds(10)); // Wait for the report to load
        String regex = "(No|\\d+\\/\\d+) security vendors flagged this file as malicious$";
        Matcher match = Pattern.compile(regex).matcher(reportSummary.getText());
        if (!match.find()) throw new RuntimeException("Upload result not found.");
        appendResultToReport(file, match.group(1));
    }

    public static boolean checkForCaptcha() {
        Selenide.sleep(500); // Wait briefly before checking for the captcha
        SelenideElement captcha = $x("//*[contains(@id, 'captcha')]/*");
        boolean captchaPresent = captcha.exists();
        if (captchaPresent) {
            Toolkit.getDefaultToolkit().beep(); // Make a sound to notify the user that a captcha is required
            captcha.shouldNot(exist, CAPTCHA_TIMEOUT); // Wait for the desired amount of time or until the user enters the captcha
        }
        return captchaPresent;
    }

    public static void scanFilesAndGenerateReport(String dirPath) {
        SelenideElement uploadInput = $(shadowCss("#fileSelector", "#view-container > home-view", "#uploadForm")).should(exist);
        SelenideElement uploadButton = $(shadowCss("div > form > button", "#view-container > home-view", "#uploadForm"));
        File dir = new File(dirPath);
        File[] files = dir.listFiles();
        assert files != null;
        for (File file : files) {
            if (file.isDirectory()) {
                scanFilesAndGenerateReport(file.getAbsolutePath());
            } else {
                uploadInput.uploadFile(file);
                Selenide.sleep(1500);
                if (uploadButton.has(text("Confirm Upload"))) uploadButton.click();

                SelenideElement report = $(shadowCss("#report", "#view-container > file-view"));

                Duration currentTime = Duration.ZERO;

                while (!report.exists()) {
                    if (checkForCaptcha()) {
                        Selenide.sleep(1500);
                        currentTime.plus(Duration.ofMillis(1500));
                        if (uploadInput.exists()) { // Sometimes VT makes you reupload after captcha.
                            uploadInput.uploadFile(file);
                            Selenide.sleep(1500);
                            currentTime.plus(Duration.ofMillis(1500));
                            if (uploadButton.has(text("Confirm Upload"))) uploadButton.click();
                        }
                    } else {
                        Selenide.sleep(1000);
                        currentTime.plus(Duration.ofSeconds(1));
                    }
                    if (currentTime.compareTo(REPORT_TIMEOUT) >= 0)
                        throw new RuntimeException("Report not found after " + REPORT_TIMEOUT.getSeconds() + " seconds."); // If the report is not found within the desired amount of time, throw an exception
                }

                collectResultsForReport(file);
                Selenide.open("https://www.virustotal.com/");
            }
        }
    }

    public static void initializeDirectories() {
        if (!reportsDir.exists() && !reportsDir.mkdirs()) {
            throw new RuntimeException("Failed to create reports directory: " + reportsDir);
        }
        if (!screenshotsDir.exists() && !screenshotsDir.mkdirs()) {
            throw new RuntimeException("Failed to create screenshots directory: " + screenshotsDir);
        }
        Configuration.reportsFolder = screenshotsDir.getAbsolutePath();
        Configuration.savePageSource = false;
    }

    public static String generateUploadResultReport(String filename, String filepath, String numberOfDetections, String vtReportURL, String reportScreenshotFilepath) {
        return String.format("""
                        <div class="upload-result">
                            <hr class="separator">
                            <h2>%s</h2>
                            <p>
                                There were <em class="detections%s">%s</em> detections for
                                <a target="_blank" href="%s">%s</a>
                            </p>
                            <a class="view-report" target="_blank" href="%s">View Report</a>
                            <br><img alt="Screenshot of VirusTotal report for %s" src="%s">
                        </div>
                        """,
                filename,
                numberOfDetections.equals("no") ? "-no" : "",
                numberOfDetections,
                filepath,
                filepath,
                vtReportURL,
                filename,
                reportScreenshotFilepath
        );
    }

    public static String generateReportHeader(String filepath, String generationTime, boolean flaggedAsMalicious) {
        return String.format("""
                        <!doctype html>
                        <title>VirusTotal Aggregated Report</title>
                        <style>
                            body {
                                background-color: #14171a;
                                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                                color: #d4d4d4;
                            }
                            header {
                                background-color: #1a202c;
                                padding: 50px;
                                margin-bottom: 20px;
                                border-radius: 1em;
                                box-shadow: 0 0.5em 1em rgba(0, 0, 0, 0.1);
                            }
                            .separator {
                                border: none; border-top: 1px solid #3a3f44; width: 100%%;
                                margin-top: 0.25em;
                                margin-bottom: 0.25em;
                            }
                            h1 {
                                font-size: 50px;
                                margin-bottom: 0.25em;
                            }
                            p, a {
                                font-size: 24px;
                                margin-bottom: 0.5em;
                            }
                            a {
                                color: #6699cc;
                            }
                            .upload-result {
                                display: flex;
                                flex-direction: column;
                                align-items: center;
                                margin-bottom: 2em;
                                padding: 1em;
                                border-radius: 0.5em;
                                box-shadow: 0 0.5em 1em rgba(0, 0, 0, 0.1);
                            }
                            .upload-result h2 {
                                font-size: 32px;
                                margin-bottom: 0.5em;
                            }
                            .upload-result p {
                                margin: 0 0 1em 0;
                            }
                            .upload-result img {
                                width: 100%%;
                                max-width: 750px;
                                margin-top: 1em;
                                border-radius: 0.5em;
                            }
                            .detections {
                                color: #cc3300;
                            }
                            .detections-no {
                                color: #009933;
                            }
                        </style>
                        <header>
                            <h1>VirusTotal Report</h1>
                            <p>
                                <strong>This is an aggregated VirusTotal report for all files that <em>%s</em> flagged as malicious from </strong><br>
                                <a target="_blank" href="%s">%s</a>
                            </p>
                            <p>This report was created <em>%s</em></p>
                        </header>
                        """,
                flaggedAsMalicious ? "were" : "were not",
                filepath,
                filepath,
                generationTime
        );
    }

    public static void initializeReports(String dir) {
        LocalDateTime now = LocalDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("MMMM dd, yyyy, hh:mm a");
        String nameOfFileToReportOn = (new File(dir)).getName().replace(' ', '_');
        File detectionsReportFile = new File(reportsDir, nameOfFileToReportOn + "_detections_report_" + now.toLocalDate().toString() + ".html");
        detectionsReportFilepath = detectionsReportFile.getAbsolutePath();
        File cleanReportFile = new File(reportsDir, nameOfFileToReportOn + "_clean_report_" + now.toLocalDate().toString() + ".html");
        cleanReportFilepath = cleanReportFile.getAbsolutePath();
        try (FileWriter reportFileWriter = new FileWriter(detectionsReportFile, false)) {
            reportFileWriter.append(generateReportHeader(dir, now.format(formatter), false));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        try (FileWriter reportFileWriter = new FileWriter(cleanReportFile, false)) {
            reportFileWriter.append(generateReportHeader(dir, now.format(formatter), false));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void scanFiles(String username, String password, String dir) {
        initializeDirectories();
        initializeReports(dir);
        openVT();
        login(username, password);
        checkForCaptcha();
        scanFilesAndGenerateReport(dir);
    }

    public static void main(String[] args) {
        if (args.length == 3)
            scanFiles(args[0], args[1], args[2]);
        else if (args.length == 1)
            scanFiles("", "", args[0]);
        else {
            System.out.println("Invalid number of arguments.");
            System.out.println("Usage: java AutoVT [<username> <password>] <dir>");
            System.exit(1);
        }
    }
}
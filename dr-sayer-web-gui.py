#!/usr/bin/env python3
"""
Dr-Sayer Web-based GUI
Author: SayerLinux (SayerLinux@outlook.sa)
Modern web interface for Dr-Sayer security testing tool
"""

from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for
import subprocess
import threading
import os
import sys
import json
import time
from datetime import datetime
from pathlib import Path

app = Flask(__name__)

# Global variables for storing test results
test_results = {}
current_test_id = None

class DrSayerWebGUI:
    def __init__(self):
        self.app = app
        self.reports_dir = Path(__file__).parent / "reports"
        self.reports_dir.mkdir(exist_ok=True)
        self.setup_routes()
    
    def setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.route('/')
        def index():
            """Main interface page"""
            return render_template('index.html')
        
        @self.app.route('/api/start_test', methods=['POST'])
        def start_test():
            """Start security testing"""
            global current_test_id, test_results
            
            data = request.get_json()
            url = data.get('url', '').strip()
            tests = data.get('tests', [])
            report_format = data.get('report_format', 'html')
            output_file = data.get('output_file', '').strip()
            accept_risk = data.get('accept_risk', False)
            attack_surface_ar = data.get('attack_surface_ar', '')
            attack_vector_ar = data.get('attack_vector_ar', '')
            oob_callback = data.get('oob_callback', '')
            
            # Validation
            if not accept_risk:
                return jsonify({'error': 'يجب قبول المسؤولية القانونية'}), 400
            
            if not url or not (url.startswith('http://') or url.startswith('https://')):
                return jsonify({'error': 'الرجاء إدخال رابط صالح يبدأ بـ http:// أو https://'}), 400
            
            if not tests:
                return jsonify({'error': 'الرجاء اختيار نوع الاختبار'}), 400
            
            # Generate test ID
            test_id = f"test_{int(time.time())}"
            current_test_id = test_id
            
            # Initialize test results
            test_results[test_id] = {
                'status': 'running',
                'url': url,
                'tests': tests,
                'report_format': report_format,
                'output_file': output_file,
                'start_time': datetime.now().isoformat(),
                'output': '',
                'return_code': None
            }
            
            # Start testing in background thread
            thread = threading.Thread(
                target=self.run_security_test,
                args=(test_id, url, tests, report_format, output_file, 
                      attack_surface_ar, attack_vector_ar, oob_callback)
            )
            thread.daemon = True
            thread.start()
            
            return jsonify({
                'test_id': test_id,
                'message': 'تم بدء الاختبار بنجاح',
                'status': 'running'
            })
        
        @self.app.route('/api/test_status/<test_id>')
        def test_status(test_id):
            """Get test status and output"""
            if test_id not in test_results:
                return jsonify({'error': 'Test not found'}), 404
            
            result = test_results[test_id].copy()
            return jsonify(result)
        
        @self.app.route('/api/reports')
        def list_reports():
            """List available reports"""
            reports = []
            for report_file in self.reports_dir.glob('*'):
                if report_file.is_file():
                    stat = report_file.stat()
                    reports.append({
                        'name': report_file.name,
                        'size': stat.st_size,
                        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        'path': str(report_file)
                    })
            
            # Sort by modification time (newest first)
            reports.sort(key=lambda x: x['modified'], reverse=True)
            return jsonify(reports)
        
        @self.app.route('/api/download_report/<filename>')
        def download_report(filename):
            """Download report file"""
            report_path = self.reports_dir / filename
            if report_path.exists() and report_path.is_file():
                return send_file(str(report_path), as_attachment=True)
            else:
                return jsonify({'error': 'Report not found'}), 404
        
        @self.app.route('/api/delete_report/<filename>', methods=['DELETE'])
        def delete_report(filename):
            """Delete report file"""
            report_path = self.reports_dir / filename
            if report_path.exists() and report_path.is_file():
                report_path.unlink()
                return jsonify({'message': 'تم حذف التقرير'})
            else:
                return jsonify({'error': 'Report not found'}), 404
    
    def run_security_test(self, test_id, url, tests, report_format, output_file, 
                          attack_surface_ar, attack_vector_ar, oob_callback):
        """Run security test in background"""
        global test_results
        
        try:
            # Build command
            cmd = [sys.executable, 'dr-sayer.py', '-u', url, '--accept-risk', '--report', report_format]
            
            # Add test options
            if 'all' in tests:
                cmd.append('--all')
            else:
                if 'sql' in tests:
                    cmd.append('--sql')
                if 'xss' in tests:
                    cmd.append('--xss')
                if 'log4j' in tests:
                    cmd.append('--log4j')
                if 'waf' in tests:
                    cmd.append('--waf-bypass')
                if 'http' in tests:
                    cmd.append('--http-inspector')
            
            # Add OOB options if needed
            if 'oob' in tests and oob_callback:
                cmd.extend(['--oob-attacks', '--oob-callback', oob_callback])
            
            # Add output file
            if output_file:
                cmd.extend(['-o', output_file])
            
            # Add Arabic text options
            if attack_surface_ar:
                cmd.extend(['--attack-surface-ar', attack_surface_ar])
            if attack_vector_ar:
                cmd.extend(['--attack-vector-ar', attack_vector_ar])
            
            # Run command
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=os.path.dirname(__file__)
            )
            
            # Collect output
            output_lines = []
            for line in process.stdout:
                output_lines.append(line)
                test_results[test_id]['output'] = ''.join(output_lines)
            
            # Wait for completion
            return_code = process.wait()
            test_results[test_id]['return_code'] = return_code
            test_results[test_id]['status'] = 'completed' if return_code == 0 else 'failed'
            test_results[test_id]['end_time'] = datetime.now().isoformat()
            
        except Exception as e:
            test_results[test_id]['status'] = 'error'
            test_results[test_id]['error'] = str(e)
            test_results[test_id]['end_time'] = datetime.now().isoformat()

def create_html_template():
    """Create HTML template for the web interface"""
    template_dir = Path(__file__).parent / 'templates'
    template_dir.mkdir(exist_ok=True)
    
    html_template = '''<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dr-Sayer - واجهة اختبار الأمان</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.rtl.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        .main-container {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            margin: 20px auto;
            max-width: 1200px;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 20px 20px 0 0;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5rem;
            font-weight: bold;
        }
        .header p {
            margin: 10px 0 0 0;
            font-size: 1.1rem;
            opacity: 0.9;
        }
        .content {
            padding: 30px;
        }
        .form-section {
            background: #f8f9fa;
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 25px;
            border-left: 5px solid #667eea;
        }
        .form-section h3 {
            color: #667eea;
            margin-bottom: 20px;
            font-size: 1.3rem;
        }
        .test-option {
            background: white;
            border: 2px solid #e9ecef;
            border-radius: 10px;
            padding: 15px;
            margin-bottom: 15px;
            transition: all 0.3s ease;
            cursor: pointer;
        }
        .test-option:hover {
            border-color: #667eea;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.2);
        }
        .test-option.selected {
            border-color: #667eea;
            background: rgba(102, 126, 234, 0.05);
        }
        .test-option input[type="checkbox"] {
            transform: scale(1.2);
            margin-left: 10px;
        }
        .test-option label {
            font-weight: 500;
            cursor: pointer;
            margin: 0;
        }
        .test-option .description {
            font-size: 0.9rem;
            color: #6c757d;
            margin-top: 5px;
        }
        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            border-radius: 10px;
            padding: 12px 30px;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(102, 126, 234, 0.3);
        }
        .output-console {
            background: #1e1e1e;
            color: #ffffff;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            border-radius: 10px;
            padding: 20px;
            max-height: 400px;
            overflow-y: auto;
            margin-top: 20px;
        }
        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-left: 10px;
        }
        .status-running { background-color: #ffc107; animation: pulse 1s infinite; }
        .status-completed { background-color: #28a745; }
        .status-failed { background-color: #dc3545; }
        .status-error { background-color: #6c757d; }
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }
        .warning-box {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 10px;
            padding: 15px;
            margin-bottom: 20px;
        }
        .warning-box i {
            color: #856404;
            margin-left: 10px;
        }
        .arabic-section textarea {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            font-size: 1rem;
        }
        .report-list {
            max-height: 300px;
            overflow-y: auto;
        }
        .report-item {
            background: white;
            border: 1px solid #e9ecef;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 10px;
            transition: all 0.3s ease;
        }
        .report-item:hover {
            border-color: #667eea;
            box-shadow: 0 3px 10px rgba(102, 126, 234, 0.1);
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="main-container">
            <div class="header">
                <h1><i class="fas fa-shield-alt"></i> Dr-Sayer</h1>
                <p>أداة اختبار أمان المواقع الإلكترونية</p>
            </div>
            
            <div class="content">
                <!-- Warning Section -->
                <div class="warning-box">
                    <i class="fas fa-exclamation-triangle"></i>
                    <strong>تحذير قانوني:</strong> هذه الأداة مخصصة للاختبار الأمني المصرح به فقط. 
                    أنت المسؤول عن التأكد من حصولك على التفويض المناسب. استخدام هذه الأداة بدون تفويض قد يخالف القوانين المعمول بها.
                </div>
                
                <!-- Configuration Form -->
                <form id="configForm">
                    <!-- Target URL -->
                    <div class="form-section">
                        <h3><i class="fas fa-globe"></i> إعدادات الهدف</h3>
                        <div class="row">
                            <div class="col-md-8">
                                <label for="targetUrl" class="form-label">رابط الهدف</label>
                                <input type="url" class="form-control" id="targetUrl" placeholder="https://example.com" required>
                            </div>
                            <div class="col-md-4">
                                <label for="reportFormat" class="form-label">نسق التقرير</label>
                                <select class="form-select" id="reportFormat">
                                    <option value="html">HTML</option>
                                    <option value="json">JSON</option>
                                    <option value="txt">نصي</option>
                                </select>
                            </div>
                        </div>
                        <div class="row mt-3">
                            <div class="col-md-8">
                                <label for="outputFile" class="form-label">اسم ملف التقرير (اختياري)</label>
                                <input type="text" class="form-control" id="outputFile" placeholder="report.html">
                            </div>
                            <div class="col-md-4">
                                <label for="oobCallback" class="form-label">OOB Callback (اختياري)</label>
                                <input type="text" class="form-control" id="oobCallback" placeholder="collaborator.example.com">
                            </div>
                        </div>
                    </div>
                    
                    <!-- Test Selection -->
                    <div class="form-section">
                        <h3><i class="fas fa-bug"></i> اختيار الاختبارات</h3>
                        <div class="row">
                            <div class="col-md-6">
                                <div class="test-option" onclick="toggleTest('all')">
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="test_all" name="tests" value="all">
                                        <label class="form-check-label" for="test_all">
                                            <strong>جميع الاختبارات</strong>
                                        </label>
                                    </div>
                                    <div class="description">تشغيل جميع اختبارات الأمان المتاحة</div>
                                </div>
                                
                                <div class="test-option" onclick="toggleTest('sql')">
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="test_sql" name="tests" value="sql">
                                        <label class="form-check-label" for="test_sql">
                                            <strong>حقن SQL</strong>
                                        </label>
                                    </div>
                                    <div class="description">اختبار ثغرات حقن SQL</div>
                                </div>
                                
                                <div class="test-option" onclick="toggleTest('xss')">
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="test_xss" name="tests" value="xss">
                                        <label class="form-check-label" for="test_xss">
                                            <strong>Cross-Site Scripting (XSS)</strong>
                                        </label>
                                    </div>
                                    <div class="description">اختبار ثغرات XSS</div>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="test-option" onclick="toggleTest('log4j')">
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="test_log4j" name="tests" value="log4j">
                                        <label class="form-check-label" for="test_log4j">
                                            <strong>Log4j</strong>
                                        </label>
                                    </div>
                                    <div class="description">اختبار ثغرة Log4j</div>
                                </div>
                                
                                <div class="test-option" onclick="toggleTest('waf')">
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="test_waf" name="tests" value="waf">
                                        <label class="form-check-label" for="test_waf">
                                            <strong>WAF Bypass</strong>
                                        </label>
                                    </div>
                                    <div class="description">اختبار تجاوز جدار الحماية</div>
                                </div>
                                
                                <div class="test-option" onclick="toggleTest('http')">
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="test_http" name="tests" value="http">
                                        <label class="form-check-label" for="test_http">
                                            <strong>HTTP Inspector</strong>
                                        </label>
                                    </div>
                                    <div class="description">فحص رؤوس HTTP وملفات تعريف الارتباط</div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="row mt-3">
                            <div class="col-md-12">
                                <div class="test-option" onclick="toggleTest('oob')">
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="test_oob" name="tests" value="oob">
                                        <label class="form-check-label" for="test_oob">
                                            <strong>Out-of-Band Attacks</strong>
                                        </label>
                                    </div>
                                    <div class="description">اختبارات SSTI، XXE، SSRF (تتطلب OOB Callback)</div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Arabic Text Sections -->
                    <div class="form-section arabic-section">
                        <h3><i class="fas fa-language"></i> حقول عربية للتقرير</h3>
                        <div class="row">
                            <div class="col-md-6">
                                <label for="attackSurfaceAr" class="form-label">سطح الاستغلال والهجوم</label>
                                <textarea class="form-control" id="attackSurfaceAr" rows="3" placeholder="وصف سطح الاستغلال والهجوم باللغة العربية"></textarea>
                            </div>
                            <div class="col-md-6">
                                <label for="attackVectorAr" class="form-label">متجه الهجوم</label>
                                <textarea class="form-control" id="attackVectorAr" rows="3" placeholder="وصف متجه الهجوم باللغة العربية"></textarea>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Legal Agreement -->
                    <div class="form-check mb-3">
                        <input class="form-check-input" type="checkbox" id="acceptRisk" required>
                        <label class="form-check-label" for="acceptRisk">
                            <strong>أقرّ أن لدي تفويضاً وأنني أتحمل المسؤولية القانونية لاستخدام هذه الأداة</strong>
                        </label>
                    </div>
                    
                    <!-- Action Buttons -->
                    <div class="d-grid gap-2 d-md-flex justify-content-md-end">
                        <button type="button" class="btn btn-outline-secondary" onclick="loadReports()">
                            <i class="fas fa-folder-open"></i> عرض التقارير
                        </button>
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-play"></i> بدء الاختبار
                        </button>
                    </div>
                </form>
                
                <!-- Test Status -->
                <div id="testStatus" class="mt-4" style="display: none;">
                    <div class="form-section">
                        <h3><i class="fas fa-info-circle"></i> حالة الاختبار</h3>
                        <div class="d-flex align-items-center">
                            <span id="statusIndicator" class="status-indicator"></span>
                            <span id="statusText">جاري الاختبار...</span>
                        </div>
                        <div id="outputConsole" class="output-console"></div>
                    </div>
                </div>
                
                <!-- Reports Section -->
                <div id="reportsSection" class="mt-4" style="display: none;">
                    <div class="form-section">
                        <h3><i class="fas fa-file-alt"></i> التقارير المتاحة</h3>
                        <div id="reportsList" class="report-list"></div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    
    <script>
        let currentTestId = null;
        let statusInterval = null;
        
        // Toggle test selection
        function toggleTest(testType) {
            const checkbox = document.getElementById(`test_${testType}`);
            checkbox.checked = !checkbox.checked;
            
            // Handle special cases
            if (testType === 'all') {
                const allCheckboxes = document.querySelectorAll('input[name="tests"]');
                allCheckboxes.forEach(cb => {
                    if (cb.value !== 'all') {
                        cb.checked = checkbox.checked;
                    }
                });
            } else if (testType === 'oob') {
                const oobCallback = document.getElementById('oobCallback');
                if (checkbox.checked && !oobCallback.value) {
                    oobCallback.focus();
                }
            }
        }
        
        // Form submission
        document.getElementById('configForm').addEventListener('submit', function(e) {
            e.preventDefault();
            startTest();
        });
        
        // Start test function
        function startTest() {
            if (!document.getElementById('acceptRisk').checked) {
                alert('يجب قبول المسؤولية القانونية');
                return;
            }
            
            const url = document.getElementById('targetUrl').value;
            if (!url) {
                alert('الرجاء إدخال رابط الهدف');
                return;
            }
            
            const tests = Array.from(document.querySelectorAll('input[name="tests"]:checked')).map(cb => cb.value);
            if (tests.length === 0) {
                alert('الرجاء اختيار نوع الاختبار');
                return;
            }
            
            const data = {
                url: url,
                tests: tests,
                report_format: document.getElementById('reportFormat').value,
                output_file: document.getElementById('outputFile').value,
                accept_risk: true,
                attack_surface_ar: document.getElementById('attackSurfaceAr').value,
                attack_vector_ar: document.getElementById('attackVectorAr').value,
                oob_callback: document.getElementById('oobCallback').value
            };
            
            // Show status section
            document.getElementById('testStatus').style.display = 'block';
            document.getElementById('statusIndicator').className = 'status-indicator status-running';
            document.getElementById('statusText').textContent = 'جاري الاختبار...';
            document.getElementById('outputConsole').textContent = '';
            
            // Hide reports section
            document.getElementById('reportsSection').style.display = 'none';
            
            fetch('/api/start_test', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data)
            })
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    alert(data.error);
                    document.getElementById('testStatus').style.display = 'none';
                } else {
                    currentTestId = data.test_id;
                    checkTestStatus();
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('حدث خطأ في بدء الاختبار');
                document.getElementById('testStatus').style.display = 'none';
            });
        }
        
        // Check test status
        function checkTestStatus() {
            if (!currentTestId) return;
            
            fetch(`/api/test_status/${currentTestId}`)
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        console.error('Error:', data.error);
                        return;
                    }
                    
                    // Update output
                    if (data.output) {
                        document.getElementById('outputConsole').textContent = data.output;
                        document.getElementById('outputConsole').scrollTop = document.getElementById('outputConsole').scrollHeight;
                    }
                    
                    // Update status
                    if (data.status === 'completed') {
                        document.getElementById('statusIndicator').className = 'status-indicator status-completed';
                        document.getElementById('statusText').textContent = 'اكتمل الاختبار بنجاح!';
                        if (statusInterval) {
                            clearInterval(statusInterval);
                            statusInterval = null;
                        }
                        loadReports();
                    } else if (data.status === 'failed') {
                        document.getElementById('statusIndicator').className = 'status-indicator status-failed';
                        document.getElementById('statusText').textContent = 'فشل الاختبار';
                        if (statusInterval) {
                            clearInterval(statusInterval);
                            statusInterval = null;
                        }
                    } else if (data.status === 'error') {
                        document.getElementById('statusIndicator').className = 'status-indicator status-error';
                        document.getElementById('statusText').textContent = 'حدث خطأ: ' + (data.error || '');
                        if (statusInterval) {
                            clearInterval(statusInterval);
                            statusInterval = null;
                        }
                    }
                    
                    // Continue checking if still running
                    if (data.status === 'running') {
                        statusInterval = setTimeout(checkTestStatus, 1000);
                    }
                })
                .catch(error => {
                    console.error('Error checking status:', error);
                });
        }
        
        // Load reports
        function loadReports() {
            fetch('/api/reports')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('reportsSection').style.display = 'block';
                    const reportsList = document.getElementById('reportsList');
                    
                    if (data.length === 0) {
                        reportsList.innerHTML = '<p class="text-muted">لا توجد تقارير متاحة</p>';
                        return;
                    }
                    
                    reportsList.innerHTML = data.map(report => `
                        <div class="report-item">
                            <div class="d-flex justify-content-between align-items-center">
                                <div>
                                    <strong>${report.name}</strong>
                                    <br>
                                    <small class="text-muted">
                                        الحجم: ${formatFileSize(report.size)} | 
                                        التعديل: ${new Date(report.modified).toLocaleString('ar-SA')}
                                    </small>
                                </div>
                                <div>
                                    <button class="btn btn-sm btn-outline-primary" onclick="downloadReport('${report.name}')">
                                        <i class="fas fa-download"></i> تحميل
                                    </button>
                                    <button class="btn btn-sm btn-outline-danger" onclick="deleteReport('${report.name}')">
                                        <i class="fas fa-trash"></i> حذف
                                    </button>
                                </div>
                            </div>
                        </div>
                    `).join('');
                })
                .catch(error => {
                    console.error('Error loading reports:', error);
                });
        }
        
        // Download report
        function downloadReport(filename) {
            window.open(`/api/download_report/${filename}`, '_blank');
        }
        
        // Delete report
        function deleteReport(filename) {
            if (confirm(`هل أنت متأكد من حذف التقرير: ${filename}؟`)) {
                fetch(`/api/delete_report/${filename}`, {
                    method: 'DELETE'
                })
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        alert(data.error);
                    } else {
                        alert(data.message);
                        loadReports();
                    }
                })
                .catch(error => {
                    console.error('Error deleting report:', error);
                });
            }
        }
        
        // Format file size
        function formatFileSize(bytes) {
            if (bytes === 0) return '0 بايت';
            const k = 1024;
            const sizes = ['بايت', 'كيلوبايت', 'ميجابايت', 'جيجابايت'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
        
        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            loadReports();
        });
    </script>
</body>
</html>'''
    
    # Write template to file
    template_file = template_dir / 'index.html'
    template_file.write_text(html_template, encoding='utf-8')

def main():
    """Main function to run the web GUI"""
    # Create HTML template
    create_html_template()
    
    # Initialize and run the web GUI
    gui = DrSayerWebGUI()
    
    print("🚀 بدء تشغيل واجهة Dr-Sayer الويبية...")
    print("📱 فتح المتصفح على: http://localhost:5000")
    print("🌐 للوصول من الأجهزة الأخرى: http://[عنوان-الآي-بي]:5000")
    print("⚠️  تأكد من أنك تستخدم هذه الأداة فقط للاختبار المصرح به!")
    
    # Try to open browser automatically
    try:
        import webbrowser
        webbrowser.open('http://localhost:5000')
    except:
        pass
    
    # Run the Flask app
    app.run(host='0.0.0.0', port=5000, debug=False)

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f"An error occurred: {e}")
        import traceback
        traceback.print_exc()
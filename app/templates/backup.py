
@login_required
def scan(request, id):
    scan = Scan.objects.get(pk=id)
    certificates = Certificate.objects.filter(scan=id).order_by('id')
    permissions = Permission.objects.filter(scan=id).order_by('id')
    activities = Activity.objects.filter(scan=id).order_by('id')
    components_intents = get_components_intents(id)
    strings = String.objects.filter(scan=id).order_by('type')
    findings = Finding.objects.filter(scan=id).exclude(severity=Severity.NO).order_by('id')
    findings_by_category = order_findings_by_categories(findings)
    database = DatabaseInfo.objects.filter(scan=scan)
    files = File.objects.filter(scan=scan)
    findings_by_severity = get_findings_by_severity(id)
    best_practices = Finding.objects.filter(scan=id, severity=Severity.NO).order_by('id')
    all_practices = Pattern.objects.filter(default_severity=Severity.NO).order_by('id')
    try:
        antivirus_scan = VirusTotalScan.objects.filter(scan=scan).latest('created_on')
        antivirus = Antivirus.objects.filter(virus_scan=antivirus_scan).order_by('id')
    except Exception:
        antivirus_scan = False
        antivirus = False
    return render(request, 'scan.html', {
        'scan' : scan,
        'permissions': permissions,
        'findings': findings,
        'certificates': certificates,
        'categories': Pattern.objects.all().order_by('id'),
        'findings_ordered': findings_by_category,
        'findings_by_severity': findings_by_severity,
        'all_practices': all_practices,
        'best_practices': best_practices,
        'activities': activities,
        'components_intents': components_intents,
        'files': files,
        'strings' : strings,
        'database': database,
        'antivirus_scan': antivirus_scan,
        'antivirus': antivirus,
        'settings': settings,
    })

def order_findings_by_categories(findings):
    finding_list = {}
    for finding in findings:
        if (finding.type):
            category_id = finding.type.id
        else:
            category_id = 1
        if not category_id in finding_list.keys():
            finding_list[category_id] = []
        finding_list[category_id].append(finding)
    return finding_list

def get_findings_by_severity(scan_id):
    return {
        'Critical': Finding.objects.filter(scan=scan_id, severity=Severity.CR).count(),
        'High': Finding.objects.filter(scan=scan_id, severity=Severity.HI).count(),
        'Medium': Finding.objects.filter(scan=scan_id, severity=Severity.ME).count(),
        'Low': Finding.objects.filter(scan=scan_id, severity=Severity.LO).count(),
        'None': Finding.objects.filter(scan=scan_id, severity=Severity.NO).count(),
    }


def get_components_intents(scan_id):
    components = Component.objects.filter(scan=scan_id)
    components_intents = list()
    for component in components:
        intents = IntentFilter.objects.filter(component=component)
        components_intents.append((component, intents))
    return components_intents


@login_required
def findings(request, scan_id=''):
    findings = []
    scan = ''
    if request.method == 'POST':
        delete = request.POST.get("delete_findings", "")
        edit = request.POST.get("edit_findings", "")
        view = request.POST.get("view_findings", "")
        status = request.POST.get("status", "")
        severity = request.POST.get("severity", "")
        push_dojo = request.POST.get("push_dojo", "")
        scan = request.POST.get("scan", "")
        findings_list = request.POST.items()
        ok = False
        for finding, value in findings_list:
            try:
                finding = int(finding)
                if isinstance(finding, int):
                    f = Finding.objects.get(pk=finding)
                    if (delete):
                        s = Scan.objects.get(pk=scan)
                        f.delete()
                        s.findings = s.findings - 1
                        s.save()
                        return redirect(reverse('scan', kwargs={"id": scan}))
                    else:
                        if (edit):
                            if (status):
                                f.status = status
                            if (severity):
                                f.severity = severity
                            f.save()
                            ok = True
                        findings.append(f)
                    if (push_dojo and settings.DEFECTDOJO_ENABLED):
                        analysis.create_finding_on_dojo(f)
            except Exception as e:
                logger.debug(e)
        if (edit and ok):
            messages.success(request, 'Edited successfully')
    else:
        if (scan_id):
            findings = Finding.objects.filter(scan=scan_id).exclude(severity=Severity.NO).order_by('id')
        else:
            findings = Finding.objects.all().exclude(severity=Severity.NO).order_by('id')
    return render(request, 'findings.html', {
        'findings': findings,
        'scan': scan,
        'settings': settings,
    })

@login_required
def finding(request, id):
    finding = Finding.objects.get(pk=id)
    return render(request, 'finding.html', {
        'finding': finding,
        'settings': settings,
    })

@login_required
def create_finding(request, scan_id = ''):
    if request.method == 'POST':
        form = FindingForm(request.POST)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.user = request.user
            form_saved = obj.save()
            scan = obj.scan
            scan.findings = int(scan.findings) + 1
            scan.save()
            messages.success(request, 'Form submission successful')
            return render(request, 'create_finding.html', {
                'form': form,
                'finding': obj.id
            })
    else:
        if (scan_id == ''):
            form = FindingForm()
        else:
            scan = Scan.objects.get(pk=scan_id)
            form = FindingForm(initial={'scan': scan})
    return render(request, 'create_finding.html', {
        'form': form,
    })

@login_required
def edit_finding(request, id):
    if request.method == 'POST':
        finding = Finding.objects.get(pk=id)
        form = FindingForm(request.POST, instance=finding)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.user = request.user
            form_saved = obj.save()
            messages.success(request, 'Form submission successful')
    else:
        finding = Finding.objects.get(pk=id)
        form = FindingForm(instance=finding, initial={'status': finding.status, 'severity': finding.severity})
    return render(request, 'edit_finding.html', {
        'form': form,
        'finding': id,
    })

@login_required
def finding_view_file(request, id):
    finding = Finding.objects.get(pk=id)
    lines = analysis.get_lines(finding)
    return render(request, 'file.html', {
        'lines': lines,
        'finding': finding.line_number,
    })

@login_required
def view_file(request, id):
    f = File.objects.get(pk=id)
    lines = analysis.get_lines(path=f.path)
    return render(request, 'file.html', {
        'lines': lines,
    })

@login_required
def patterns(request):
    if request.method == 'POST':
        status = request.POST.get("status", "")
        patterns = request.POST.items()
        for pattern, value in patterns:
            try:
                pattern = int(pattern)
                if isinstance(pattern, int):
                    p = Pattern.objects.get(pk=pattern)
                    if (status == 'active'):
                        p.active = True
                    elif (status == 'inactive'):
                        p.active = False
                    p.save()
            except Exception as e:
                logger.error(e)
    patterns = Pattern.objects.all()
    return render(request, 'patterns.html', {
        'patterns': patterns,
    })

@login_required
def permissions(request):
    permissions = PermissionType.objects.all()
    return render(request, 'permissions.html', {
        'permissions': permissions,
    })

@login_required
def malware(request):
    malwares = Malware.objects.all()
    return render(request, 'malware.html', {
        'malwares': malwares,
    })



    findings_by_severity = get_findings_by_severity(id)
    best_practices = Finding.objects.filter(scan=id, severity=Severity.NO)
    all_practices = Pattern.objects.filter(default_severity=Severity.NO)
    
        'findings_by_severity': findings_by_severity,
        'all_practices': all_practices,
        'best_practices': best_practices,


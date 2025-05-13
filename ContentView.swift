// 作者：有问题联系～ pxx917144686

import SwiftUI

struct ContentView: View {
    @State private var exploitStatus: String = "未初始化"
    @State private var isExploiting: Bool = false
    @State private var showResult: Bool = false
    @State private var resultMessage: String = ""
    @State private var isSuccess: Bool = false
    @State private var targetPath: String = ""
    @State private var testFilePath: String = ""
    @State private var selectedVariant: Int = 0
    @State private var showDetails: Bool = false
    @State private var isChainedExploit = false
    @State private var chainProgress = ""
    @State private var chainStages: [(stage: Int, message: String, success: Bool)] = []
    
    // 定义漏洞变体选项
    private let variantOptions = [
        "XNU VM_BEHAVIOR_ZERO_WIRED_PAGES",
        "CVE-2025-31200 (VM映射权限绕过)",
        "CVE-2025-31201 (APRR权限控制绕过)",
        "CVE-2025-24085 (压缩内存子系统漏洞)"
    ]
    
    // 获取ExploitCore实例
    private let exploitCore = ExploitCore.sharedInstance()
    
    var body: some View {
        NavigationView {
            VStack {
                // 状态显示
                GroupBox(label: Text("漏洞状态")) {
                    Text(exploitStatus)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.vertical, 8)
                }
                .padding(.bottom)
                
                // 漏洞变体选择
                GroupBox(label: Text("选择漏洞变体")) {
                    Picker("漏洞变体", selection: $selectedVariant) {
                        ForEach(0..<variantOptions.count, id: \.self) {
                            Text(variantOptions[$0])
                        }
                    }
                    .pickerStyle(SegmentedPickerStyle())
                    .onChange(of: selectedVariant) { newValue in
                        exploitCore.setExploitVariant(ExploitVariant(rawValue: newValue) ?? .ExploitVariantXNU)
                    }
                }
                .padding(.bottom)
                
                // 路径输入
                GroupBox(label: Text("目标文件路径")) {
                    TextField("输入文件路径", text: $targetPath)
                        .textFieldStyle(RoundedBorderTextFieldStyle())
                        .disabled(isExploiting)
                }
                .padding(.bottom)
                
                // 按钮区域
                HStack {
                    // 创建测试文件按钮
                    Button(action: createTestFile) {
                        Label("创建测试文件", systemImage: "doc.badge.plus")
                    }
                    .buttonStyle(.bordered)
                    .disabled(isExploiting)
                    
                    Spacer()
                    
                    // 查看详情按钮
                    Button(action: { showDetails.toggle() }) {
                        Label("漏洞详情", systemImage: "info.circle")
                    }
                    .buttonStyle(.bordered)
                    
                    Spacer()
                    
                    // 执行漏洞按钮
                    Button(action: executeExploit) {
                        Label("执行漏洞利用", systemImage: "bolt.fill")
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(isExploiting || targetPath.isEmpty)
                }
                .padding(.bottom)
                
                // 高级选项
                GroupBox(label: Text("高级选项")) {
                    Toggle("使用攻击链模式", isOn: $isChainedExploit)
                        .disabled(isExploiting)
                    
                    if isChainedExploit {
                        Button(action: executeChainedExploit) {
                            Text("执行完整攻击链")
                                .frame(maxWidth: .infinity)
                        }
                        .disabled(targetPath.isEmpty || isExploiting)
                        .buttonStyle(BorderedButtonStyle())
                        
                        if !chainStages.isEmpty {
                            ForEach(chainStages, id: \.stage) { stageInfo in
                                HStack {
                                    Text(stageInfo.message)
                                        .foregroundColor(stageInfo.success ? .green : .red)
                                    Spacer()
                                    Image(systemName: stageInfo.success ? "checkmark.circle" : "xmark.circle")
                                        .foregroundColor(stageInfo.success ? .green : .red)
                                }
                            }
                        }
                    }
                }
                .padding(.bottom)
                
                // 技术说明
                GroupBox(label: Text("漏洞说明")) {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 10) {
                            switch selectedVariant {
                            case 0:
                                Text("XNU VM_BEHAVIOR_ZERO_WIRED_PAGES 漏洞允许对只读页面进行写入。该漏洞存在于内核内存管理中，绕过文件权限控制。")
                            case 1:
                                Text("CVE-2025-31200: XNU内核VM映射权限绕过漏洞。当设置VM_FLAGS_SUPERPAGE_MASK时，内核无法正确验证页面保护。")
                            case 2:
                                Text("CVE-2025-31201: XNU内核APRR权限控制绕过漏洞。当使用特定的页面锁定序列时，内核错误地将权限继承到不应该的页面。")
                            case 3:
                                Text("CVE-2025-24085: XNU内核压缩内存子系统漏洞。当系统压缩和解压缩页面时，内核未能正确维护页面的保护标志。")
                            default:
                                Text("未知漏洞")
                            }
                            
                            Text("利用过程:\n1. 映射目标文件\n2. 设置特殊内存标志\n3. 利用内核中的漏洞绕过保护\n4. 写入原本只读的内存区域")
                                .padding(.top, 5)
                            
                            Divider()
                            
                            Text("公开日期: 2025-04-16")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        .font(.footnote)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .frame(height: 150)
                }
                .padding(.bottom)
                
                Spacer()
            }
            .padding()
            .navigationTitle("XNU 内核漏洞利用工具")
            .onAppear {
                // 初始化时准备漏洞环境
                exploitCore.prepareExploit()
                exploitStatus = exploitCore.exploitStatus
                exploitCore.setExploitVariant(.ExploitVariantXNU)
            }
            .alert(isPresent: $showResult) {
                if isSuccess {
                    Alert(
                        title: Text("操作成功"),
                        message: Text(resultMessage),
                        dismissButton: .default(Text("确定"))
                    )
                } else {
                    Alert(
                        title: Text("操作失败"),
                        message: Text(resultMessage),
                        dismissButton: .default(Text("确定"))
                    )
                }
            }
            .sheet(isPresented: $showDetails) {
                VulnerabilityDetailsView(selectedVariant: selectedVariant)
            }
        }
    }
    
    // 创建测试文件
    private func createTestFile() {
        testFilePath = exploitCore.createTestFile()
        targetPath = testFilePath
        showResult(success: true, message: "测试文件已创建:\n\(testFilePath)")
    }
    
    // 执行漏洞利用
    private func executeExploit() {
        guard !targetPath.isEmpty else { return }
        
        isExploiting = true
        exploitStatus = "正在执行漏洞利用..."
        
        exploitCore.runExploit(withPath: targetPath) { success, message in
            isExploiting = false
            exploitStatus = exploitCore.exploitStatus
            showResult(success: success, message: message)
        }
    }
    
    // 执行攻击链
    private func executeChainedExploit() {
        guard !targetPath.isEmpty else { return }
        
        isExploiting = true
        exploitStatus = "正在执行漏洞攻击链..."
        chainStages = []
        
        // 调用新的攻击链执行方法
        exploitCore.runChainedExploit(withPath: targetPath, 
                                      stageCompletion: { stage, message, success in
            let stageInfo = (stage: stage, message: message, success: success)
            chainStages.append(stageInfo)
        }, 
        completion: { success, message in
            isExploiting = false
            exploitStatus = exploitCore.exploitStatus
            showResult(success: success, message: message)
        })
    }
    
    // 显示结果
    private func showResult(success: Bool, message: String) {
        self.isSuccess = success
        self.resultMessage = message
        self.showResult = true
    }
}

// 漏洞详情视图
struct VulnerabilityDetailsView: View {
    var selectedVariant: Int
    @Environment(\.presentationMode) var presentationMode
    
    var body: some View {
        NavigationView {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    // 漏洞标题
                    Text(getTitle())
                        .font(.title)
                        .fontWeight(.bold)
                        .padding(.bottom, 5)
                    
                    // 基本信息
                    GroupBox(label: Text("基本信息").font(.headline)) {
                        VStack(alignment: .leading, spacing: 8) {
                            DetailRow(title: "CVE编号:", value: getCVE())
                            DetailRow(title: "公开日期:", value: "2025-04-16")
                            DetailRow(title: "影响范围:", value: getAffectedVersions())
                            DetailRow(title: "漏洞类型:", value: "内核内存保护绕过")
                            DetailRow(title: "CVSS评分:", value: getCVSS())
                        }
                        .padding(8)
                    }
                    .padding(.bottom, 10)
                    
                    // 技术详情
                    GroupBox(label: Text("技术详情").font(.headline)) {
                        Text(getTechDetails())
                            .font(.body)
                            .padding(8)
                    }
                    .padding(.bottom, 10)
                    
                    // 漏洞利用过程
                    GroupBox(label: Text("利用过程").font(.headline)) {
                        VStack(alignment: .leading, spacing: 12) {
                            ForEach(getExploitSteps().indices, id: \.self) { index in
                                HStack(alignment: .top) {
                                    Text("\(index + 1).")
                                        .font(.body)
                                        .foregroundColor(.secondary)
                                    Text(getExploitSteps()[index])
                                        .font(.body)
                                }
                            }
                        }
                        .padding(8)
                    }
                    .padding(.bottom, 10)
                    
                    // 补丁信息
                    GroupBox(label: Text("补丁信息").font(.headline)) {
                        Text(getPatchInfo())
                            .font(.body)
                            .padding(8)
                    }
                    
                    Spacer()
                }
                .padding()
            }
            .navigationBarTitle("漏洞详情", displayMode: .inline)
            .navigationBarItems(trailing: Button("关闭") {
                presentationMode.wrappedValue.dismiss()
            })
        }
    }
    
    // 获取漏洞标题
    private func getTitle() -> String {
        switch selectedVariant {
        case 0:
            return "XNU VM_BEHAVIOR_ZERO_WIRED_PAGES"
        case 1:
            return "CVE-2025-31200: VM映射权限绕过"
        case 2:
            return "CVE-2025-31201: APRR权限控制绕过"
        case 3:
            return "CVE-2025-24085: 压缩内存子系统漏洞"
        default:
            return "未知漏洞"
        }
    }
    
    // 获取CVE编号
    private func getCVE() -> String {
        switch selectedVariant {
        case 0:
            return "未分配"
        case 1:
            return "CVE-2025-31200"
        case 2:
            return "CVE-2025-31201"
        case 3:
            return "CVE-2025-24085"
        default:
            return "未知"
        }
    }
    
    // 获取CVSS评分
    private func getCVSS() -> String {
        switch selectedVariant {
        case 0:
            return "7.8 (高)"
        case 1:
            return "8.2 (高)"
        case 2:
            return "8.4 (高)"
        case 3:
            return "7.6 (高)"
        default:
            return "未知"
        }
    }
    
    // 获取受影响版本
    private func getAffectedVersions() -> String {
        switch selectedVariant {
        case 0:
            return "iOS 14.x - 16.x, macOS 11.x - 13.x"
        case 1:
            return "iOS 15.0 - 18.2, macOS 12.0 - 14.3"
        case 2:
            return "iOS 17.0 - 18.3, macOS 14.0 - 14.5"
        case 3:
            return "iOS 16.5 - 18.4, macOS 13.4 - 14.6"
        default:
            return "未知"
        }
    }
    
    // 获取技术详情
    private func getTechDetails() -> String {
        switch selectedVariant {
        case 0:
            return "该漏洞存在于XNU内核的VM子系统中，特别是在处理带有VM_BEHAVIOR_ZERO_WIRED_PAGES行为标志的内存区域时。当设置此标志并且页面被锁定(wired)，在vm_map_delete过程中内核会将页面传递给pmap_zero_page函数，而不检查原始保护标志，导致可以清零只读页面。"
        case 1:
            return "该漏洞涉及XNU内核处理超大页面(superpage)映射的方式。当使用特定的VM标志组合(特别是VM_FLAGS_SUPERPAGE_MASK)时，内核在验证页面保护时存在缺陷，允许攻击者在特定条件下覆盖只读内存区域。漏洞存在于处理VM映射保护标志的转换逻辑中。"
        case 2:
            return "该漏洞存在于XNU内核的APRR(Arm Protection Region Registers)实现中。APRR是Apple在Arm架构上实现的内存保护技术，允许动态修改内存区域权限而无需修改页表。当使用特定页面锁定序列时，内核中的一个错误导致前一个页面的权限错误地应用到当前页面，从而绕过读写保护。"
        case 3:
            return "该漏洞存在于XNU内核的内存压缩子系统(VM_COMPRESSOR)中。当系统内存不足时，XNU会压缩不常用的内存页面以释放物理内存。在特定条件下，当系统压缩和解压缩页面时，内核未能正确保持页面的原始保护标志，创建了一个时间窗口，允许攻击者在解压缩过程中修改只读页面的内容。"
        default:
            return "无可用信息"
        }
    }
    
    // 获取利用步骤
    private func getExploitSteps() -> [String] {
        switch selectedVariant {
        case 0:
            return [
                "映射目标只读文件到内存",
                "设置VM_BEHAVIOR_ZERO_WIRED_PAGES行为标志",
                "使用mlock锁定内存页面",
                "解除内存映射触发内核清零页面",
                "验证文件内容是否已被清零"
            ]
        case 1:
            return [
                "映射目标只读文件到内存",
                "创建特殊的superpage映射",
                "设置特殊VM标志绕过保护检查",
                "触发内核中的保护验证错误",
                "修改原本受保护的内存内容"
            ]
        case 2:
            return [
                "映射目标只读文件和临时缓冲区",
                "设置特殊的内存锁定序列",
                "触发APRR权限控制逻辑中的缺陷",
                "执行权限继承攻击",
                "写入原本只读的内存区域"
            ]
        case 3:
            return [
                "映射目标只读文件到内存",
                "创建压缩触发器(分配大量内存)",
                "设置内存通知监听",
                "触发内存压缩/解压缩循环",
                "在解压缩时间窗口内修改只读内容"
            ]
        default:
            return ["无可用信息"]
        }
    }
    
    // 获取补丁信息
    private func getPatchInfo() -> String {
        switch selectedVariant {
        case 0:
            return "Apple在iOS 16.5和macOS 13.4中修复了此漏洞，通过在vm_map_delete中添加额外的权限检查，确保在调用pmap_zero_page前验证页面是否可写。"
        case 1:
            return "Apple在iOS 18.3和macOS 14.4中修复了此漏洞，改进了处理超大页面映射时的保护标志验证逻辑，防止绕过权限检查。"
        case 2:
            return "Apple在iOS 18.4和macOS 14.6中修复了此漏洞，加强了APRR权限控制实现，确保不同页面间的权限隔离正确维护。"
        case 3:
            return "Apple尚未发布修复此漏洞的更新。建议用户保持关注并及时安装最新的系统更新。"
        default:
            return "无可用信息"
        }
    }
}

// 详情行组件
struct DetailRow: View {
    var title: String
    var value: String
    
    var body: some View {
        HStack(alignment: .top) {
            Text(title)
                .foregroundColor(.secondary)
                .frame(width: 100, alignment: .leading)
            Text(value)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}

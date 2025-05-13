import SwiftUI

struct ContentView: View {
    @State private var exploitStatus: String = "未初始化"
    @State private var isExploiting: Bool = false
    @State private var showResult: Bool = false
    @State private var resultMessage: String = ""
    @State private var isSuccess: Bool = false
    @State private var targetPath: String = ""
    @State private var testFilePath: String = ""
    
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
                    
                    // 执行漏洞按钮
                    Button(action: executeExploit) {
                        Label("执行漏洞利用", systemImage: "bolt.fill")
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(isExploiting || targetPath.isEmpty)
                }
                .padding(.bottom)
                
                // 技术说明
                GroupBox(label: Text("漏洞说明")) {
                    ScrollView {
                        Text("XNU VM_BEHAVIOR_ZERO_WIRED_PAGES 漏洞允许对只读页面进行写入。该漏洞利用内核内存管理中的一个缺陷，可绕过文件权限控制。\n\n利用过程:\n1. 映射目标文件为只读内存\n2. 设置特殊内存行为标志\n3. 锁定内存页面\n4. 解除内存映射\n\n影响: 可以修改系统只读文件内容，潜在提权风险。")
                            .font(.footnote)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .frame(height: 150)
                }
                .padding(.bottom)
                
                Spacer()
            }
            .padding()
            .navigationTitle("XNU 内存漏洞利用")
            .onAppear {
                // 初始化时准备漏洞环境
                exploitCore.prepareExploit()
                exploitStatus = exploitCore.exploitStatus
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
    
    // 显示结果
    private func showResult(success: Bool, message: String) {
        self.isSuccess = success
        self.resultMessage = message
        self.showResult = true
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}

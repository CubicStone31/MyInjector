using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Diagnostics;
using Microsoft.Win32;
using System.Threading;
using System.Runtime.InteropServices;
using System.Windows.Interop;
using System.Runtime.CompilerServices;

namespace MyInjector
{
    /// <summary>
    /// MainWindow.xaml 的交互逻辑
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            SetTextboxPlaceholder(TextBox_DllPath, dllPath_PlaceholderText);
            SetTextboxPlaceholder(TextBox_ProcessFilter, processFilter_PlaceholderText);
            InitMajorNode();
        }

        private void ComboBox_ProcessList_DropDownOpened(object sender, EventArgs e)
        {
            // we dont use wpf 'DataSource' here because later we maybe want to set selected item that is not in data source
            // so we just do it legency way

            ComboBox_ProcessList.Items.Clear();

            // set filter
            processListSource.ProcessFilter = TextBox_ProcessFilter.Text == processFilter_PlaceholderText ? null : TextBox_ProcessFilter.Text;

            var data = processListSource.ProcessList;
            foreach (var process in data)
            {
                ComboBox_ProcessList.Items.Add(process);
            }          
        }

        private ProcessListSource processListSource = new ProcessListSource();

        private int GetTargetPID()
        {
            if (!(ComboBox_ProcessList.SelectedItem is string data))
            {
                return -1;
            }
            data = data.Substring(0, data.IndexOf('\t'));
            return int.Parse(data);
        }

        private string GetTargetDllPath()
        {
            return TextBox_DllPath.Text;
        }

        private void InitMajorNode()
        {
            Node_Major.Init(Injection.InjectionMethodManager.MajorNode);
            Node_Major.MethodSelected += Node_Major_MethodSelected;
            Node_Major_MethodSelected(Node_Major, new RoutedEventArgs());
        }

        private void AddInjectionNode(Injection.InjectionNode node)
        {
            var nodeControl = new MethodNode()
            {
                HorizontalAlignment = HorizontalAlignment.Stretch,
                VerticalAlignment = VerticalAlignment.Center,
            };
            nodeControl.Init(node);
            InjectionMethodArea.Children.Add(nodeControl);
            InjectionMethodArea.UpdateLayout();
        }

        private void ClearInjectionNodes()
        {
            var major = InjectionMethodArea.Children[0];
            InjectionMethodArea.Children.Clear();
            InjectionMethodArea.Children.Add(major);
            InjectionMethodArea.UpdateLayout();
        }

        private void Node_Major_MethodSelected(object sender, RoutedEventArgs e)
        {
            ClearInjectionNodes();
            var self = sender as MethodNode;
            var major_method = (self.Node as Injection.MajorNode).MajorCandidates[self.Methods.SelectedIndex];

            if (major_method.MinorNodes != null)
            {
                foreach (var node in major_method.MinorNodes)
                {
                    AddInjectionNode(node);
                }
            }

            SizeToContent = SizeToContent.Height;
            UpdateLayout();
        }

        private void TextBox_DllPath_PreviewDragOver(object sender, DragEventArgs e)
        {
            if (!(e.Data.GetData(DataFormats.FileDrop) is string[] fileNames))
            {
                return;
            }
            var fileName = fileNames.FirstOrDefault();
            if (fileName == null)
            {
                return;
            }
            (sender as TextBox).Text = fileName;
            (sender as TextBox).Foreground = Brushes.Black;
            e.Handled = true;
        }

        private readonly string dllPath_PlaceholderText = "Drag and drop your dll file here";
        private readonly string processFilter_PlaceholderText = "Process Filter";

        private void TextBox_DllPath_GotFocus(object sender, RoutedEventArgs e)
        {
            var self = sender as TextBox;
            if (self.Text.Equals(dllPath_PlaceholderText))
            {
                self.Text = "";
                self.Foreground = Brushes.Black;
            }
        }

        private void TextBox_DllPath_LostFocus(object sender, RoutedEventArgs e)
        {
            var self = sender as TextBox;
            if (self.Text.Length == 0)
            {
                SetTextboxPlaceholder(self, dllPath_PlaceholderText);
            }
        }

        private void SetTextboxPlaceholder(TextBox tbx, string text)
        {
            tbx.Text = text;
            tbx.Foreground = Brushes.Gray;
        }

        private void Button_OpenDll_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dialog = new OpenFileDialog();
            dialog.Filter = "DLL file|*.dll|All files|*.*";
            if (dialog.ShowDialog() == true)
            {
                TextBox_DllPath.Foreground = Brushes.Black;
                TextBox_DllPath.Text = dialog.FileName;
            }
        }

        private void Widget_ProcessFinder_MouseDown(object sender, MouseButtonEventArgs e)
        {
            Widget_ProcessFinder.CaptureMouse();
            WindowFramePainter.Start((int pid, string name) =>
            {
                Application.Current.Dispatcher.Invoke(() =>
                {
                    ComboBox_ProcessList.Items.Clear();
                    ComboBox_ProcessList.Items.Add(String.Format("{0}\t{1}", pid, name is null ? "[No Name]" : name));
                    ComboBox_ProcessList.SelectedIndex = 0;
                });
            });
        }

        private void Widget_ProcessFinder_MouseUp(object sender, MouseButtonEventArgs e)
        {
            Widget_ProcessFinder.ReleaseMouseCapture();
            WindowFramePainter.Stop();
        }

        protected override void OnClosed(EventArgs e)
        {
            Environment.Exit(0);
            base.OnClosed(e);
        }

        private void TextBox_ProcessFilter_GotFocus(object sender, RoutedEventArgs e)
        {
            var self = sender as TextBox;
            if (self.Text.Equals(processFilter_PlaceholderText))
            {
                self.Text = "";
                self.Foreground = Brushes.Black;
            }
        }

        private void TextBox_ProcessFilter_LostFocus(object sender, RoutedEventArgs e)
        {
            var self = sender as TextBox;
            if (self.Text.Length == 0)
            {
                SetTextboxPlaceholder(self, processFilter_PlaceholderText);
            }
        }

        private void Button_ConfirmInjection_Click(object sender, RoutedEventArgs e)
        {
            var pid = GetTargetPID();
            var dllPath = GetTargetDllPath();
            if (pid < 0 || dllPath is null || dllPath == "")
            {
                MessageBox.Show("Invalid parameter!");
                return;
            }

            List<Tuple<Injection.InjectionNode, int>> injectionMethod = new List<Tuple<Injection.InjectionNode, int>>();
            foreach (var child in InjectionMethodArea.Children)
            {
                var node = child as MethodNode;
                if (node == null)
                {
                    continue;
                }

                Tuple<Injection.InjectionNode, int> currentSelection = new Tuple<Injection.InjectionNode, int>(node.Node, node.Methods.SelectedIndex);
                injectionMethod.Add(currentSelection);
            }

            // create logger window
            var logger = new LoggerWindow();
            logger.Top = this.Top + 20;
            logger.Left = this.Left + 20;
           
            // start injection
            Thread worker = new Thread(() =>
            {
                InjectionWorker(injectionMethod, pid, dllPath, logger);
            });
            worker.Start();

            logger.ShowDialog();
        }

        private bool IsTargetX64(int pid, out bool isX64)
        {
            isX64 = false;

            if (!Environment.Is64BitOperatingSystem)
            {
                return true;
            }

            var kernel32 = GetModuleHandle("kernel32");
            var func = GetProcAddress(kernel32, "IsWow64Process");
            if (func == IntPtr.Zero)
            {
                // No IsWoW64Process() function in kernel32.dll, so the system is 32bit.
                return true;
            }
            var IsWow64Process = Marshal.GetDelegateForFunctionPointer<IsWow64ProcessType>(func);
            var processHandle = OpenProcess(0x1000, false, pid);
            if (processHandle == IntPtr.Zero)
            {
                return false;
            }
            var ret = IsWow64Process.Invoke(processHandle, out bool isOnWow);
            CloseHandle(processHandle);
            if (!ret)
            {
                return false;
            }
            if (isOnWow)
            {
                // target is running on Windows on Windows 64 subsystem, so it is a x86 process
                return true;
            }
            else
            {
                isX64 = true;
                return true;
            }
        }

        private void InjectionWorker(List<Tuple<Injection.InjectionNode, int>> injectionMethod, int pid, string dllPath, LoggerWindow logger)
        {
            bool isTargetX64;
            if (!IsTargetX64(pid, out isTargetX64))
            {
                var selection = MessageBox.Show("Failed to get target process's architecture, please set it manually.\nIs target a x64 process?", "Question", MessageBoxButton.YesNo);
                if (selection == MessageBoxResult.Yes)
                {
                    isTargetX64 = true;
                }
                else
                {
                    isTargetX64 = false;
                }
            }

            logger.LogThreadSafe(String.Format("[+] Injection start, target is {0}", isTargetX64 ? "x64" : "x86"), Brushes.Black);
            bool result = false;
            try
            {
                result = Injection.InjectionMethodManager.PerformInjection(injectionMethod, pid, isTargetX64, dllPath, (string data) =>
                {
                    logger.LogThreadSafe(data, Brushes.Black);
                });
            }
            catch (Exception e)
            {
                logger.LogThreadSafe(e.ToString(), Brushes.Red);
            }

            if (result)
            {
                logger.LogThreadSafe("[+] Injection succeeded", Brushes.Green);
            }
            else
            {
                logger.LogThreadSafe("[-] Injection failed", Brushes.Red);
            }
            logger.CanClose = true;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);


        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        delegate bool IsWow64ProcessType(IntPtr processHandle, [MarshalAs(UnmanagedType.Bool)] out bool wow64Process);
    }

    public class ProcessListSource
    {
        public string ProcessFilter { get; set; } = null;

        public IEnumerable<string> ProcessList
        {
            get
            {
                var ret = new List<string>();
                var plist = Process.GetProcesses();
                Array.Sort(plist, delegate (Process process1, Process process2)
                {
                    return process1.Id.CompareTo(process2.Id);
                });

                foreach (var process in plist)
                {
                    var pid = process.Id;
                    var pname = process.ProcessName;
                    var content = String.Format("{0}\t{1}", pid, pname);

                    if (ProcessFilter != null && ProcessFilter != "")
                    {
                        if (content.IndexOf(ProcessFilter) == -1)
                        {
                            continue;
                        }
                    }

                    ret.Add(content);
                }
                return ret;
            }
        }
    }

    public static class WindowFramePainter
    {
        /// <summary>
        /// Draw a rectange in screen, using windows cordinate system
        /// </summary>
        /// <param name="x"></param>
        /// <param name="y"></param>
        /// <param name="width"></param>
        /// <param name="height"></param>
        public static void DrawRectangleAtPos(int x, int y, int width, int height)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                marker = new MarkerWindow()
                {
                    // We cannot specify our marker window position and size here, because wpf is using a different cordinate system.
                    // If the DPI setting in windows is not 100%, wpf's cordinate system will differ from windows native
                    //Top = 0,
                    //Left = 0,
                    //Width = 0,
                    //Height = 0
                };            
                var helper = new WindowInteropHelper(marker);
                helper.EnsureHandle();
                var handle = helper.Handle;
                // use windows api to move to a proper position, regardless of system DPI setting
                SetWindowPos(handle, (IntPtr)(-1), x, y, width, height, 0x0080); // 0x0080 => Hidden
                // finally, init the window and show it 
                marker.Show();
            });
        }

        public static void Clear()
        {
            if (marker != null)
            {
                Application.Current.Dispatcher.Invoke(() =>
                {
                    marker.Close();
                });
            }
            marker = null;
        }

        public static void Start(ProcessFound processFoundCallback)
        {
            if (painterThread != null)
            {
                if (painterThread.IsAlive)
                {
                    return;
                }
                else
                {
                    painterThread = null;
                }
            }

            callback = processFoundCallback;
            exitFlag = false;
            currentWindowHandle = IntPtr.Zero;
            painterThread = new Thread(() =>
            {
                Worker();
            });
            painterThread.Start();
        }

        public static void Stop()
        {
            exitFlag = true;
            currentWindowHandle = IntPtr.Zero;
        }

        private static void Worker()
        {
            while (!exitFlag)
            {
                Thread.Sleep(200);

                if (!GetCursorPos(out NativePoint point))
                {
                    currentWindowHandle = IntPtr.Zero;
                    continue;
                }
                var handle = WindowFromPoint(point);
                if (handle == currentWindowHandle)
                {
                    continue;
                }
                currentWindowHandle = handle;
                if (!GetWindowRect(currentWindowHandle, out RECT rect))
                {
                    currentWindowHandle = IntPtr.Zero;
                    continue;
                }
                Clear();
                DrawRectangleAtPos(rect.Left, rect.Top, rect.Right - rect.Left, rect.Bottom - rect.Top);

                if (!exitFlag)
                {
                    callback?.Invoke(SelectedProcessID, SelectedProcessName);
                }
            }
            Clear();
        }

        public static int SelectedProcessID
        {
            get
            {
                if (currentWindowHandle == IntPtr.Zero)
                {
                    return -1;
                }
                GetWindowThreadProcessId(currentWindowHandle, out uint processId);
                return (int)processId;
            }
        }

        public static string SelectedProcessName
        {
            get
            {
                if (currentWindowHandle == IntPtr.Zero)
                {
                    return null;
                }
                GetWindowThreadProcessId(currentWindowHandle, out uint processId);
                var proc = Process.GetProcessById((int)processId);
                return proc is null ? null : proc.ProcessName;
            }
        }

        private static bool exitFlag = false;
        private static MarkerWindow marker = null;
        private static Thread painterThread = null;
        private static IntPtr currentWindowHandle = IntPtr.Zero;
        private static ProcessFound callback;
        public delegate void ProcessFound(int pid, string processName);

        [StructLayout(LayoutKind.Sequential)]
        public struct RECT
        {
            public int Left;        // x position of upper-left corner
            public int Top;         // y position of upper-left corner
            public int Right;       // x position of lower-right corner
            public int Bottom;      // y position of lower-right corner
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct NativePoint
        {
            public int x;
            public int y;
        }

        [DllImport("user32.dll")]
        private static extern IntPtr WindowFromPoint(NativePoint p);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool GetWindowRect(IntPtr hwnd, out RECT lpRect);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetCursorPos(out NativePoint lpPoint);

        [DllImport("user32.dll", SetLastError = true)]
        static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);

        [DllImport("user32.dll", SetLastError = true)]
        static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, int uFlags);
    }
}

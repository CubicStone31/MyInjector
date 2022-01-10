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
using System.Windows.Shapes;

namespace MyInjector
{
    /// <summary>
    /// LoggerWindow.xaml 的交互逻辑
    /// </summary>
    public partial class LoggerWindow : Window
    {
        public LoggerWindow()
        {
            InitializeComponent();
            Closing += new System.ComponentModel.CancelEventHandler(MyWindow_Closing);
        }

        public bool CanClose { get; set; } = false;

        public void Log(string data, Brush color)
        {
            var now = DateTime.Now;
            var p1 = now.ToString("T");
            var p2 = now.ToString("fff");
            var timestamp = p1 + "." + p2;
            var p = new Paragraph(new Run(timestamp + "\t" + data))
            {
                Margin = new Thickness(1, 1, 1, 1),
                Foreground = color
            };
            DataArea.Blocks.Add(p);
        }

        public void LogThreadSafe(string data, Brush color)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                Log(data, color);
            });
        }

        void MyWindow_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            if (!CanClose)
            {
                Log("Injection in progress, close this window later!", Brushes.Red);
                e.Cancel = true;
            }
        }
    }
}

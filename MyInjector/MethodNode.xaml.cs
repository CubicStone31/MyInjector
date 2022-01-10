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

namespace MyInjector
{
    /// <summary>
    /// MethodNode.xaml 的交互逻辑
    /// </summary>
    public partial class MethodNode : UserControl
    {
        public MethodNode()
        {
            InitializeComponent();
        }

        public event RoutedEventHandler MethodSelected;
        public Injection.InjectionNode Node { get; private set; } = null;

        public void Init(Injection.InjectionNode node)
        {
            Node = node;
            Methods.Items.Clear();
            foreach (var candiate in Node.Candidates)
            {
                Methods.Items.Add(candiate.Name);
            }
            Methods.SelectedIndex = Node.DefaultCandidate;
            TypeName.Content = node.Name;
        }

        private void Methods_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            var selected = Methods.SelectedItem as string;
            foreach (var candiate in Node.Candidates)
            {
                if (candiate.Name == selected)
                {
                    Description.Content = candiate.Description;
                }
            }

            MethodSelected?.Invoke(this, new RoutedEventArgs());
        }
    }
}

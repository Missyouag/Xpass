using System.Diagnostics;
using System.Windows.Forms;

namespace Xpass
{
    public partial class Form1 : Form
    {
        private string[]? selectedFiles;
        private string? selectedDir;
        private string? selectedType;
        public Form1()
        {
            InitializeComponent();
        }

        private void Button1_Click(object sender, EventArgs e)
        {
            // ����û������ "ȷ��" ��ť
            if (openFileDialog1.ShowDialog(this) == DialogResult.OK)
            {
                // ��ȡ�û�ѡ����ļ�·��
                selectedFiles = openFileDialog1.FileNames;

                if (selectedFiles != null)
                {
                    selectedType = "file";
                    // ��� RichTextBox
                    richTextBox1.Clear();

                    // �������ÿ��Ԫ��д�� RichTextBox��ÿ��Ԫ��ռ��һ��
                    foreach (string element in selectedFiles)
                    {
                        richTextBox1.AppendText(element + Environment.NewLine);
                    }
                }

            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            if (folderBrowserDialog1.ShowDialog(this) == DialogResult.OK)
            {
                selectedDir = folderBrowserDialog1.SelectedPath;
                if (selectedDir != null)
                {
                    selectedType = "dir";
                    // ��� RichTextBox
                    richTextBox1.Clear();

                    selectedDir = folderBrowserDialog1.SelectedPath;
                    richTextBox1.AppendText(selectedDir);

                }
            }
        }

        private void button3_Click(object sender, EventArgs e)
        {
            Debug.WriteLine(selectedType);
            switch (selectedType)
            {
                case "file":
                    break;
                case "dir":
                    break;
                default:
                    MessageBox.Show(this, "��ѡ���ļ�����Ŀ¼��", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Information); ;
                    break;
            }
        }
    }
}

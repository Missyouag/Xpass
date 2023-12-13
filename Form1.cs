using System.Windows.Forms;

namespace Xpass
{
    public partial class Form1 : Form
    {
        private List<string> selectedFiles = [];
        public Form1()
        {
            InitializeComponent();
        }

        private void SelectFilesButton_Click(object sender, EventArgs e)
        {
            // ����û������ "ȷ��" ��ť
            if (openFileDialog1.ShowDialog(this) == DialogResult.OK)
            {

                if (openFileDialog1.FileNames.Length > 0)
                {
                    pathRichTextBox.Clear();
                    selectedFiles.Clear();
                    // ��ȡ�û�ѡ����ļ�·��
                    selectedFiles.AddRange(openFileDialog1.FileNames);

                    // �������ÿ��Ԫ��д�� RichTextBox��ÿ��Ԫ��ռ��һ��
                    foreach (string element in selectedFiles)
                    {
                        pathRichTextBox.AppendText(element + Environment.NewLine);
                    }
                }

            }
        }

        private void SelectDirButton_Click(object sender, EventArgs e)
        {
            if (folderBrowserDialog1.ShowDialog(this) == DialogResult.OK)
            {
                if (!string.IsNullOrEmpty(folderBrowserDialog1.SelectedPath))
                {
                    // ��� RichTextBox
                    pathRichTextBox.Clear();
                    selectedFiles.Clear();
                    pathRichTextBox.AppendText(folderBrowserDialog1.SelectedPath);
                    selectedFiles = Xclass.GetXshFiles(folderBrowserDialog1.SelectedPath);

                }
            }
        }

        private void AppendText(string text, Color color)
        {
            resultRichTextBox.SelectionStart = resultRichTextBox.TextLength;
            resultRichTextBox.SelectionLength = 0;

            resultRichTextBox.SelectionColor = color;
            resultRichTextBox.AppendText(text);
            resultRichTextBox.SelectionColor = resultRichTextBox.ForeColor;
        }
        private void DecryptButton_Click(object sender, EventArgs e)
        {
            if (selectedFiles.Count > 0)
            {
                string sid;
                if (masterPasswdTextBox.Text.Length > 0)
                {
                    sid = masterPasswdTextBox.Text;
                }
                else
                {
                    sid = Xclass.GetSid();
                }

                resultRichTextBox.Clear();
                int index = 1;
                foreach (string element in selectedFiles)
                {
                    resultRichTextBox.AppendText(index + "��" + element + Environment.NewLine);
                    var session = Xclass.FileParser(element, sid);
                    resultRichTextBox.AppendText("    Host��" + session.host + Environment.NewLine);
                    resultRichTextBox.AppendText("    Port��" + session.port + Environment.NewLine);
                    resultRichTextBox.AppendText("    UserName��" + session.userName + Environment.NewLine);
                    if (session.isok)
                    {
                        resultRichTextBox.AppendText("    Password��" + session.password + Environment.NewLine);
                    }
                    else
                    {
                        AppendText("    Password������ʧ�ܣ�ȷ���������Ƿ���ȷ��" + Environment.NewLine, Color.Red);
                    }

                    resultRichTextBox.ScrollToCaret();
                    index++;
                }
            }
            else
            {
                MessageBox.Show(this, "��ѡ���ļ�����Ŀ¼��", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        private void showPasswdCheckBox_CheckedChanged(object sender, EventArgs e)
        {
            if (showPasswdCheckBox.Checked)
            {
                masterPasswdTextBox.PasswordChar = '\0';
            }
            else
            {
                masterPasswdTextBox.PasswordChar = '*';
            }
        }
    }



}
